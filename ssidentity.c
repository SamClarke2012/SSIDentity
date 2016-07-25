/*
            WIRESHARK FILTERS
Frame type                 Filter
Management frames         wlan.fc.type eq 0
Control frames             wlan.fc.type eq 1
Data frames                 wlan.fc.type eq 2

Frame subtype             Filter
Association request         wlan.fc.type_subtype eq 0
Association response    wlan.fc.type_subtype eq 1
Probe request             wlan.fc.type_subtype eq 4
Probe response             wlan.fc.type_subtype eq 5
Beacon                     wlan.fc.type_subtype eq 8
Authentication             wlan.fc.type_subtype eq 11
Deauthentication         wlan.fc.type_subtype eq 12

            SQLite3 REFERENCE
https://www.sqlite.org/c3ref/intro.html

** Use airmon-ng to enable promiscuous mode ** 
** For the moment, it's easier to debug.    **

CLIENT (This) TODOs

    # Move timestamp to epoch
    # Use MAC as primary Key and keep timestamps as CSV text field
    # Handle UTF-8 and other crap leaking through isprint()

    # Add remote admin capability (edit settings / modes)
    # Add DB upload to server based on settings
    # Add distance filtering based on settings

SERVER (Coming) TODOs

    # Add Triangulation (Trilateration Estimation) 
    # Add 

*/

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
// isalnum
#include <ctype.h>
// memset
#include <string.h>
// FSPL equations
#include <math.h>
// SQL
#include <sqlite3.h> 
// Socket
#include <netinet/if_ether.h>
// IP Header structs
#include <netinet/ip.h>
// Local
#include "ssidentity.h"
// Verbose Assertions
#include "cAssert.h"


static int sqlCallback(void *NotUsed, int argc, char **argv, char **azColName){
   return 0;
}

int main( int argc, char **argv ) {
    //SQL vars
    char *sqlCmd;
    char *sqlErr;
    sqlite3 *requestDB;
    int rc = sqlite3_open("observations.db", &requestDB);
    cAssertMsg((rc <= 0), "Failed to open observations.db\n");
    // Buffer for received 80211 frames
    uint8_t pktBuff[PKT_BUFF_SZ];
    // Setup a scoket for *any* protocol
    struct sockaddr socketAddr;
    socklen_t addrLen = sizeof(socketAddr);
    // Family, type, protocol
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    cAssertMsg( (sock >= 0), "Are you running as root?\n");

    while(TRUE) {
        // Receive without needing a socket connection 
        int recvDataSize = recvfrom( sock, pktBuff, PKT_BUFF_SZ,
                                     NOFLAG, &socketAddr, &addrLen);
        // Parse it if it's a probe request
        Request request = parseRaw(pktBuff, recvDataSize);
        // Print it if it's not null
        if( request != NULL ){ 
            printf("%s  %s  \"%s\"\t%ddBm %umHz  Dist: %.02fm\n", 
                request->timeStamp,
                request->clientMAC, 
                request->SSID,
                request->RSSI,
                request->frequency,
                request->distance);
            // Add a new entry to the db
            sqlCmd = sqlite3_mprintf("INSERT INTO obs "
                    "(TIMESTAMP, MAC, SSID, RSSI, FREQ, DIST)"
                    " VALUES ('%q', '%q', '%q', %d, %u, %.02f);", 
                    request->timeStamp,
                    request->clientMAC, 
                    request->SSID,
                    request->RSSI,
                    request->frequency,
                    request->distance);
            /* Execute SQL statement */
            rc = sqlite3_exec(requestDB, sqlCmd, sqlCallback, 0, &sqlErr);
            if( rc != SQLITE_OK ){
                // printf(stderr, "SQL error: %s\n", sqlErr);
                sqlite3_free(sqlErr);
            }
        }
        free(request);  
    }

    return EXIT_SUCCESS;
}


/*
\x08\x01\x18\x10\x07\x08\x0A\x0C�   �
    Parse 802.11 probe requests from raw socket data.
    Since this is an open, promiscuous socket..The data
    could really be anything.

    If the data yields;
        - The correct frame protocol at the correct offset
        - A broadcast MAC at the correct offset
        - A valid SSID length
        - Isn't a known protocol (IP layer)

    It is then considered a valid probe request.
*/
Request parseRaw( uint8_t *buff, uint16_t buffSize ) {
    // Get the frame protocol out
    int16_t frameProtocol = (buff[FRAME_CTL_OFFSET] & 0xF0) >> 4;
    // Get frame header as iphdr struct
    struct iphdr *ip_header;
    ip_header = (struct iphdr *)(buff + sizeof(struct ethhdr));
    // Get frame protocol
    int protocol = ip_header->protocol;
    // Skip known ethernet protocols and non broadcast frames
    // If statements are eval'd in order, ordered for fast rejection.
    if( frameProtocol == IEEE80211_STYPE_PROBE_REQ &&
        isBroascast( &buff[DEST_ADDR_OFFSET])      &&
        !isKnownProtocol( protocol )               ){
        // Begin decoding the frame
        int i, validSSID;
        validSSID = TRUE;
        // Throw a new request onto the heap
        Request request = malloc( sizeof( RequestStruct ) );
        // Preformat the SSID with NULL chars
        memset(request->SSID, '\0', SSID_BUFF_SZ);
        // Check the SSID isn't blank or ovrflw
        uint8_t SSIDlen = buff[SSID_LEN_OFFSET];
        if( SSIDlen > 0 && SSIDlen <= SSID_BUFF_SZ ) {
            // Copy SSID into request
            for(i = 0; i < SSIDlen; i++){
                // If it's a printable char
                if( isprint(buff[SSID_CHR_OFFSET + i]) && validSSID ) {
                    request->SSID[i] = buff[SSID_CHR_OFFSET + i];
                // Otherwise it's something interesting...log it.
                } else {
                    // Convert it to a '\xNN' string rep
                    char hexByte[5];
                    snprintf(&hexByte[0], 5, "\\x%02X",
                            (unsigned char)buff[SSID_CHR_OFFSET + i]);
                    // Set the SSID to printable HEX
                    request->SSID[i] = hexByte[0];
                    request->SSID[i+1] = hexByte[1];
                    request->SSID[i+2] = hexByte[2];
                    request->SSID[i+3] = hexByte[3];
                    // Kick i fwd a few spots
                    i+=3;
                    validSSID = FALSE;
                }
            }
            // Now get client MAC as uint64
            uint64_t longMac = macU8ToU64( &buff[MAC_ADDR_OFFSET] );
            // Make a HEX string from it
            snprintf(request->clientMAC, 32, "%012lX", longMac);
            // Give the request a time-stamp
            setTimeStamp( request );
            // Set the RSSI
            request->RSSI = buff[RSSI_OFFSET] - 0xFF;
            // Set the frequency
            request->frequency  = (buff[FREQ_OFFSET] & 0xFF) << 8;
            request->frequency |= (buff[FREQ_OFFSET+1] & 0xFF);
            // set the distance estimate
            request->distance = signalToDistance(request->RSSI, 
                                                 request->frequency);
            // Tell me if you see that bus go past
            if(!validSSID) infoRed("Found that weird STA bus...\n");
            // Return the request
            return request;
        } else {
            // SSID length was outside spec
            return NULL;
        }
    } else {
        // Frame protocol other than probe request
        return NULL;
    }
} 

/*
    Time stamp a request.
    It's a shame dealing with time in C is such a pain.
*/
void setTimeStamp( Request request ) {
    // Epoch
    time_t rawtime;
    // Time tm struct
    struct tm *info;
    // Buffer for string rep
    char buffer[80];
    // Fill the struct
    time( &rawtime );
    info = localtime( &rawtime );
    // Format the timestamp string
    strftime(request->timeStamp, TIME_BUFF_SZ ,"%x - %I:%M%p", info);
}

/*
    Check a decoded IP header protocol against known 
    protocols. Return true if it's;
        -UDP
        -TCP
        -IGMP
        -ICMP
*/
int isKnownProtocol( int protocol ) {
    if( protocol == PROTO_UDP  || protocol == PROTO_TCP ||
        protocol == PROTO_IGMP || protocol == PROTO_ICMP ) {
        return TRUE;
    } else {
        return FALSE;
    }
}

/*
    Check 6 bytes of a buffer for a broadcast MAC.
    uint8_t *buff should point to the first byte
    of the MAC. 

    Assumes 6 bytes in buff.
*/
int isBroascast( uint8_t *buff ) {
    if( buff[5] == 0xFF && buff[4] == 0xFF && 
        buff[3] == 0xFF && buff[2] == 0xFF && 
        buff[1] == 0xFF && buff[0] == 0xFF ) {
        return TRUE;
    } else {
        return FALSE;
    }
}

/*
    Shift a MAC address into a 64 bit unsigned int.
    Useful for converting to a string.
*/
uint64_t macU8ToU64( uint8_t *mac ) {
    uint64_t macint;
    // MAC bytes into a long
    macint =  (uint64_t)(mac[0] & 0xFF) << (8*5);
    macint |= (uint64_t)(mac[1] & 0xFF) << (8*4);
    macint |= (uint64_t)(mac[2] & 0xFF) << (8*3);
    macint |= (uint64_t)(mac[3] & 0xFF) << (8*2);
    macint |= (uint64_t)(mac[4] & 0xFF) <<  8;
    macint |= (uint64_t) mac[5] & 0xFF;
    return macint;
}

/*
    Get an estimate of device distance from freq and RSSI.
    Uses "free space path loss" equation.

    https://en.wikipedia.org/wiki/Free-space_path_loss
    for MHz / meters,

    RSSI = FSPL(dB) = 20*log10( dist ) + 20*log10( freq ) - 27.55
*/
float signalToDistance( int8_t RSSI, uint16_t frequency ) {
    float distance = (27.55-RSSI-(20*log10(frequency)))/20.00;
    return (float)pow(10, distance); 
}