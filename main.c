#include <stdio.h>
#include <conio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
// header files to be included

char ethPreamble[17] = "55555555555555d5";
const char allowedCharacters[17] = "0123456789abcdef";
char ipV4Type[5] = "0800";
char serviceTag[5] = "88a8";
char customerTag[5] = "8100";
// global variables to be set



typedef struct Ipv4Info{
    uint8_t dscp;         /* IPv4 DSCP field value */
    uint8_t protocol;     /* IPv4 protocol field value */
    bool optionsPresent;  /* Are IPv4 options present in the packet? */
} Ipv4Info;


bool CheckType (char * r, int indexEth, char text[5])
{
    for(int i = 0; i < 4; i++)
    {
        if((char)text[i] != (char)r[indexEth])
        {
            return false;
        }
        indexEth++;
    }
    return true;

}

void binaryToHex(const char *inStr, char *outStr) {
    // outStr must be at least strlen(inStr)/4 + 1 bytes.
    static char hex[] = "0123456789abcdef";
    int len = strlen(inStr) / 4;
    int i = len % 4;
    char current = 0;
    if(i) { // handle not multiple of 4
        while(i--) {
            current = (current << 1) + (*inStr - '0');
            inStr++;
        }
        *outStr = hex[current];
        ++outStr;
    }
    while(len--) {
        current = 0;
        for(i = 0; i < 4; ++i) {
            current = (current << 1) + (*inStr - '0');
            inStr++;
        }
        *outStr = hex[current];
        ++outStr;
    }
    *outStr = 0; // null byte
    }

// implemeneted for binary buffer
bool ethIpv4Parse (const void* buffer, size_t bufLen, Ipv4Info* info)
{
    //conversion from bin to hex
    const char * inStr = (char*)buffer;
    char * r;

    binaryToHex(inStr, r);

    printf(r);



    size_t buflenCheck;
    buflenCheck = strlen(r);

    //if buflen doesn't match, return false
    if (bufLen/4 != buflenCheck){
        return false;
    }

    // first we check if preamble is set correctly
    for(int i = 0; i < 16; i++){
        if((char)r[i] != (char)ethPreamble[i])
        {
            printf("Failed");
            return false;
        }
    }

    // check if Destination Mac and Source Mac are set correctly
    for(int i = 0; i < 24; i++){
        if(strchr(allowedCharacters, (char)r[i+16]) == NULL)
        {
            printf(allowedCharacters);
            printf("%c\n", r[i+16]);
            printf("Failed");
            return false;
        }
    }

    // first index of potential ethertype data field
    int ethernetIndex = 40;
    bool chckType;
    // check if etherType at index 40 and ending at index 43 is IPV4
    chckType = CheckType(r, ethernetIndex, ipV4Type);

    // if not ipv4 type, check for VLAN tags
    if (chckType == false)
    {
        //check service VLAN tag
        chckType = CheckType(r, ethernetIndex, serviceTag);

        if (chckType == false)
        {
            //check customer VLAN tag
            chckType = CheckType(r, ethernetIndex, customerTag);

            if (chckType == false)
            {
                return false;
            }
            else
            {
                ethernetIndex = ethernetIndex + 8;
                // check if next 8 bytes are also VLAN customer tag
                chckType = CheckType(r, ethernetIndex, customerTag);
                if (chckType == false)
                {
                    chckType = CheckType(r, ethernetIndex, ipV4Type);

                    if (chckType == false)
                    {
                        return false;
                    }
                }
                else
                {
                    ethernetIndex = ethernetIndex + 8;
                }
            }
        }
        else
        {
            ethernetIndex = ethernetIndex + 8;
            // if ehtType is of service VLAN tag, check if after 8 bytes if customer VLAN tag
            chckType = CheckType(r, ethernetIndex, customerTag);

            if (chckType == false)
            {
                return false;
            }
            else
            {
                ethernetIndex = ethernetIndex + 8;
            }
        }
    }

    // check with new index

    chckType = CheckType(r, ethernetIndex, ipV4Type);
    if (chckType == false)
    {
        return false;
    }
    else
    {
        uint8_t dscp;  char dscpC[3]; int dscpbitShift;
        uint8_t protocol; char protocolC[3];
        bool optionsPresent; char optionsC[2]; int optionsInt;

        ethernetIndex = ethernetIndex + 5;
        strncpy ( optionsC, r+ethernetIndex, 1);
        optionsInt = (int)strtol(optionsC, NULL, 16);

        if (optionsInt > 5){

            optionsPresent = true;
        }
        else
        {
            optionsPresent = false;
        }

        ethernetIndex = ethernetIndex + 1;
        strncpy ( dscpC, r+ethernetIndex, 2);
        dscpbitShift = (int)strtol(dscpC, NULL, 16);
        dscp = dscpbitShift >> 2;

        ethernetIndex = ethernetIndex + 16;
        strncpy ( protocolC, r+ethernetIndex, 2);
        protocol = (int)strtol(protocolC, NULL, 16);

        info->dscp = dscp;
        info->protocol = protocol;
        info->optionsPresent = optionsPresent;



        return true;
    }


}


int main()
{
    FILE* file = fopen("pretvorba.txt", "r");
    char line[4096];
    int i = 0;

    // we chose type of ethernet packet (1 for without VLAN tagging, 4 and 7 with VLAN tagging and 10 invalid) hex versions
    // 2,5,8,11 for binary versions
    while (fgets(line, sizeof(line), file)) {
        i++;
        if(i == 14)
        {
            break;
        }
    }
    fclose(file);

    Ipv4Info ipInfo;

    Ipv4Info *tdInfo = &ipInfo;

    const void* buffer = &line;

    size_t buflen;
    // minus 1 because of newline character
    buflen = strlen(buffer) -1;

    bool isIPv4;

    // our function for parsing ethPacket
    isIPv4 = ethIpv4Parse(buffer, buflen, tdInfo);

    return isIPv4;
}
