/*
    Definitions for ssidentity.c
    - 802.11 proto
    - Local defines
*/
#include <stdint.h>

#define TRUE   1
#define FALSE  0
#define NOFLAG 0

#define TIME_BUFF_SZ 128
#define SSID_BUFF_SZ 32
#define MAC_BUFF_SZ  32
// Needs to be sized for arbitrary protocols
#define PKT_BUFF_SZ  65536
// IP packet protocols
#define PROTO_ICMP 1
#define PROTO_IGMP 2
#define PROTO_TCP  6
#define PROTO_UDP  17
// 802.11 management protocols
#define IEEE80211_STYPE_ASSOC_REQ       0x00
#define IEEE80211_STYPE_ASSOC_RESP      0x01
#define IEEE80211_STYPE_REASSOC_REQ     0x02
#define IEEE80211_STYPE_REASSOC_RESP    0x03
#define IEEE80211_STYPE_PROBE_REQ       0x04
#define IEEE80211_STYPE_PROBE_RESP      0x05
#define IEEE80211_STYPE_BEACON          0x08
#define IEEE80211_STYPE_ATIM            0x09
#define IEEE80211_STYPE_DISASSOC        0x0A
#define IEEE80211_STYPE_AUTH            0x0B
#define IEEE80211_STYPE_DEAUTH          0x0C
#define IEEE80211_STYPE_ACTION          0x0D
// 802.11 frame offsets (not so POSIX)
#define FRAME_CTL_OFFSET 26
#define SSID_LEN_OFFSET  51
#define SSID_CHR_OFFSET  52
#define MAC_ADDR_OFFSET  36
#define DEST_ADDR_OFFSET 42
#define RSSI_OFFSET      22
#define FREQ_OFFSET      19

typedef struct _req *Request;

typedef struct _req{
    // String timestamp of
    char timeStamp[TIME_BUFF_SZ];
    // Device MAC
    char clientMAC[MAC_BUFF_SZ];
    // Requesting station
    char SSID[SSID_BUFF_SZ];
    // On frequency
    uint16_t frequency;
    // With signal strength
    int8_t RSSI;
    // Which imples
    float distance;
} req;


Request parseRaw( uint8_t *buff, uint16_t buffSize );
int isBroadcast( uint8_t *buff );
int isKnownProtocol( int protocol );
uint64_t macU8ToU64( uint8_t *mac );
void setTimeStamp( Request request );
float signalToDistance( int8_t RSSI, uint16_t frequency );
