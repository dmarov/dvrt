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

    // verify that a reader interface was indeed created
    if (reader == NULL)
    {
        printf("Cannot determine reader for file type\n");
        exit(1);
    }

    // open the reader for reading
    if (!reader->open())
    {
        printf("Cannot open input.pcap for reading\n");
        exit(1);
    }

    // read the first (and only) packet from the file
    pcpp::RawPacket rawPacket;
    if (!reader->getNextPacket(rawPacket))
    {
        printf("Couldn't read the first packet in the file\n");
        return 1;
    }

    // close the file reader, we don't need it anymore
    reader->close();


    // parse the raw packet into a parsed packet
    pcpp::Packet parsedPacket(&rawPacket);

    // now let's get the Ethernet layer
    pcpp::EthLayer* ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
    // change the source dest MAC address
    // change the source dest MAC address
    ethernetLayer->setDestMac(pcpp::MacAddress("aa:bb:cc:dd:ee:ff"));

    // let's get the IPv4 layer
    pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    // change source IP address
    ipLayer->setSrcIpAddress(pcpp::IPv4Address(std::string("1.1.1.1")));
    // change IP ID
    ipLayer->getIPv4Header()->ipId = htons(4000);
    // change TTL value
    ipLayer->getIPv4Header()->timeToLive = 12;

    // let's get the TCP layer
    pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
    // change source port
    tcpLayer->getTcpHeader()->portSrc = htons(12345);
    // add URG flag
    tcpLayer->getTcpHeader()->urgFlag = 1;
    // add MSS TCP option
    tcpLayer->addTcpOptionAfter(pcpp::TcpOptionBuilder(pcpp::TCPOPT_MSS, (uint16_t)1460));

    // compute all calculated fields
    parsedPacket.computeCalculateFields();

    // write the modified packet to a pcap file
    pcpp::PcapFileWriterDevice writer("dbd1-modified.pcap");
    writer.open();
    writer.writePacket(*(parsedPacket.getRawPacket()));
    writer.close();
}
