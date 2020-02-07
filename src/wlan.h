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
#define IEID_EXT			 255  //11ax HE
#define EXTID_HECAPABILITIES 35
#define EXTID_HEOPERATION    36

const int DIV_HT = 8;
const double HT_MCSRate[8][4] = { 
// HT20, HT20 SGI, HT40, HT40 SGI
	{ 6.5,  7.2,  13.5,  15},
	{13.0, 14.4,  27.0,  30},
	{19.5, 21.7,  40.5,  45},
	{26.0, 28.9,  54.0,  60},
	{39.0, 43.3,  81.0,  90},
	{52.0, 57.8, 108.0, 120},
	{58.5, 65.0, 121.5, 135},
	{65.0, 72.2, 135.0, 150}
};
const int DIV_VHT = 10;
const double VHT_MCSRate[10][8] = {
// HT20, HT20 SGI, HT40, HT40 SGI, HT80, HT80 SGI, HT160, HT160 SGI
	{ 6.5,  7.2,  13.5,  15,  29.3,  32.5,  58.5,  65.0}, // 0
	{13.0, 14.4,  27.0,  30,  58.5,  65.0, 117.0, 130.0}, // 1
	{19.5, 21.7,  40.5,  45,  87.8,  97.5, 175.5, 195.0}, // 2
	{26.0, 28.9,  54.0,  60, 117.0, 130.0, 234.0, 260.0}, // 3
	{39.0, 43.3,  81.0,  90, 175.5, 195.0, 351.0, 390.0}, // 4
	{52.0, 57.8, 108.0, 120, 234.0, 260.0, 468.0, 520.0}, // 5
	{58.5, 65.0, 121.5, 135, 263.3, 292.5, 526.5, 585.0}, // 6
	{65.0, 72.2, 135.0, 150, 292.5, 325.0, 585.0, 650.0}, // 7
	{78.0, 86.7, 162.0, 180, 351.0, 390.0, 702.0, 780.0}, // 8
	{ 0.0,  0.0, 180.0, 200, 390.0, 433.3, 780.0, 866.7} // 9
};
const int DIV_HE = 12;
const double HE_MCSRate[12][12] = {
//20-0.8, 20-1.6, 20-3.2, 40-0.8, 40-1.6, 40-3.2, 80-0.8, 80-1.6, 80-3.2, 160-0.8, 160-1.6, 160-3.2, 
	{  8.6,   8.1,   7.3,  17.2,  16.3,  14.6,  36.0,  34.0,  30.6,   72.1,   68.1,   61.3},
	{ 17.2,  16.3,  14.6,  34.4,  32.5,  29.3,  72.1,  68.1,  61.3,  144.1,  136.1,  122.5},
	{ 25.8,  24.4,  21.9,  51.6,  48.8,  43.9, 108.1, 102.1,  91.9,  216.2,  204.2,  183.8},
	{ 34.4,  32.5,  29.3,  68.8,  65.0,  58.5, 144.1, 136.1, 122.5,  288.2,  272.2,  245.0},
	{ 51.6,  48.8,  43.9, 103.2,  97.5,  87.8, 216.2, 204.2, 183.8,  432.4,  408.3,  367.5},
	{ 68.8,  65.0,  58.5, 137.6, 130.0, 117.0, 288.2, 272.2, 245.0,  576.5,  544.4,  490.0},
	{ 77.4,  73.1,  65.8, 154.9, 146.3, 131.6, 324.3, 306.3, 275.6,  648.5,  612.5,  551.3},
	{ 86.0,  81.3,  73.1, 172.1, 162.5, 146.3, 360.3, 340.3, 306.3,  720.6,  680.6,  612.5},
	{103.2,  97.5,  87.8, 206.5, 195.0, 175.5, 432.4, 408.3, 367.5,  864.7,  816.7,  735.0},
	{114.7, 108.3,  97.5, 229.4, 216.7, 195.0, 480.4, 453.7, 408.3,  960.8,  907.4,  816.7},
	{129.0, 121.9, 109.7, 258.1, 243.8, 219.4, 540.4, 510.4, 459.4, 1080.9, 1020.8,  918.8},
	{143.4, 135.4, 121.9, 286.8, 270.8, 243.8, 600.5, 567.1, 510.4, 1201.0, 1134.3, 1020.8}
};

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383


#endif // _WLAN_H