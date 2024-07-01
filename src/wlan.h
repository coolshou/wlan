#pragma once

#ifndef _WLAN_H

#include <bitset>
using std::bitset;
#pragma pack(push, 1)
typedef struct _HTCapa
{
	bitset<16> info;
	bitset<8> mcs07;
	bitset<8>  ampdu;

	bitset<8> mcs1623;
	bitset<8> mcs815;

	bitset<8> mcs2431;
	bitset<1> mcs32;
	bitset<6> mcs3338;
	bitset<14> mcs3952;
	bitset<24> mcs5376;
	bitset<10> mcs_highest;
	bitset<1> mcs_tx;
	bitset<1> mcs_txrx;
	bitset<2> mcs_maxtx;
	bitset<1> mcs_moduletion;

	bitset<16> htextcapa;
	bitset<32> txbf;
	bitset<8>  asel;

}HTCapa, * pHTCapa;
#pragma pack(pop)

constexpr std::uint_fast8_t mask0{ 0x1 }; // hex for 0000 0001 
constexpr std::uint_fast8_t mask1{ 0x2 }; // hex for 0000 0010
constexpr std::uint_fast8_t mask2{ 0x4 }; // hex for 0000 0100
constexpr std::uint_fast8_t mask3{ 0x8 }; // hex for 0000 1000
constexpr std::uint_fast8_t mask4{ 0x10 }; // hex for 0001 0000
constexpr std::uint_fast8_t mask5{ 0x20 }; // hex for 0010 0000
constexpr std::uint_fast8_t mask6{ 0x40 }; // hex for 0100 0000
constexpr std::uint_fast8_t mask7{ 0x80 }; // hex for 1000 0000
/*
constexpr std::uint_fast8_t mask8{0x100}; // hex for 0001 0000 0000
constexpr std::uint_fast8_t mask9{ 0x200 }; // hex for 0010 0000 0000
constexpr std::uint_fast8_t mask10{ 0x400 }; // hex for 0100 0000 0000
constexpr std::uint_fast8_t mask11{ 0x800 }; // hex for 1000 0000 0000
constexpr std::uint_fast8_t mask12{ 0x1000 }; // hex for 0001 0000 0000 0000
constexpr std::uint_fast8_t mask13{ 0x2000 }; // hex for 0010 0000 0000 0000
constexpr std::uint_fast8_t mask14{ 0x4000 }; // hex for 0100 0000 0000 0000
constexpr std::uint_fast8_t mask15{ 0x8000 }; // hex for 1000 0000 0000 0000
*/
// Information elements
#define IEID_HTCAPABILITIES  45
#define IEID_HTINFORMATION   61
#define IEID_INTERWORKING    107
#define IEID_ADVPROTOCOL     108
#define IEID_EXPBANDREQ      109
#define IEID_QOSMAPSET       110
#define IEID_ROAMCONS        111
#define IEID_EMERALERTID     112 
#define IEID_VHTCAPABILITIES 191
#define IEID_VHTOPERATION    192
#define IEID_VENDORSPEC	     221	
#define IEID_EXT			 255  
#define EXTID_HECAPABILITIES 35  //11ax HE CAPABILITIES
#define EXTID_HEOPERATION    36  //11ax HE OPERATION
#define EXTID_EHTOPERATION    106  //11be EHT CAPABILITIES
#define EXTID_EHTCAPABILITIES 108  //11be EHT OPERATION

#include "ht_rate.h"
#include "vht_rate.h"
#include "he_rate.h"
#include "eht_rate.h"

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383


#endif // _WLAN_H