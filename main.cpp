#if !defined(WIN32) && !defined(WINx64)
#include <in.h> // this is for using ntohs() and htons() on non-Windows OS's
#endif
#include "stdlib.h"
#include "Packet.h"
#include "EthLayer.h"
#include "VlanLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "HttpLayer.h"
#include "UdpLayer.h"
#include "DnsLayer.h"
#include "PcapFileDevice.h"

int main(int argc, char* argv[])
{
    // use the IFileReaderDevice interface to automatically identify file type (pcap/pcap-ng)
    // and create an interface instance that both readers implement
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader("dbd1.pcap");
    pcpp::PcapFileWriterDevice writer("dbd1-modified.pcap");

    // verify that a reader interface was indeed created
    if (reader == NULL)
    {
        printf("Cannot determine reader for file type\n");
        exit(1);
    }

    reader->open();
    writer.open();

    pcpp::RawPacket rawPacket;

    while(reader->getNextPacket(rawPacket)) {

        pcpp::Packet parsedPacket(&rawPacket);

        pcpp::EthLayer* ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
        ethernetLayer->setDestMac(pcpp::MacAddress("aa:bb:cc:dd:ee:ff"));

        parsedPacket.computeCalculateFields();

        writer.writePacket(*(parsedPacket.getRawPacket()));
    }

    reader->close();
    writer.close();
}
