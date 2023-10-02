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

void decToHex(char outStr[5], long decNumber) {

  long remainder;
  int j = 3;
  //input outStr should be = "0000";
  if (decNumber < 0) {
    decNumber = 65535 + decNumber;
  }

  while (decNumber != 0) {
    remainder = decNumber % 16;
    if (remainder < 10)
      outStr[j--] = 48 + remainder;
    else
      outStr[j--] = 55 + remainder;
    decNumber = decNumber / 16;
  }
}


bool ethIpv4Parse (const void* buffer, size_t bufLen, Ipv4Info* info)
{
    //printf((char*)buffer);

    char *r = (char*)buffer;
    printf("%c\n",r[0]);

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
    char line[2048];
    int i = 0;
    while (fgets(line, sizeof(line), file)) {
        i++;
        if(i == 1)
        {
            break;
        }
    }
    fclose(file);

    Ipv4Info ipInfo;

    Ipv4Info *tdInfo = &ipInfo;
    //tdInfo = malloc(sizeof(ipInfo));

    tdInfo->dscp = 11;
    tdInfo->protocol = 22;
    tdInfo->optionsPresent = false;

    //ipInfo.protocol = 231;
    printf("%d\n",tdInfo->protocol);

    const void* buffer = &line;

    size_t buflen;
    buflen = strlen(buffer);

    bool isIPv4;

    isIPv4 = ethIpv4Parse(buffer, buflen, tdInfo);

    return isIPv4;
}
