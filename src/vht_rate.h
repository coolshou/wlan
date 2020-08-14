#pragma once

#ifndef _VHT_RATE_H
#define _VHT_RATE_H

const int DIV_VHT = 10;
const double VHT_MCSRate[12][8] = {
	  // HT20,HT20S, HT40,HT40S, HT80,  HT80S, HT160,HT160S
		{ 6.5,  7.2,  13.5,  15,  29.3,  32.5,  58.5,  65.0}, // 0, BPSK
		{13.0, 14.4,  27.0,  30,  58.5,  65.0, 117.0, 130.0}, // 1, QPSK
		{19.5, 21.7,  40.5,  45,  87.8,  97.5, 175.5, 195.0}, // 2, QPSK
		{26.0, 28.9,  54.0,  60, 117.0, 130.0, 234.0, 260.0}, // 3, 16-QAM
		{39.0, 43.3,  81.0,  90, 175.5, 195.0, 351.0, 390.0}, // 4, 16-QAM
		{52.0, 57.8, 108.0, 120, 234.0, 260.0, 468.0, 520.0}, // 5, 64-QAM 
		{58.5, 65.0, 121.5, 135, 263.3, 292.5, 526.5, 585.0}, // 6, 64-QAM 
		{65.0, 72.2, 135.0, 150, 292.5, 325.0, 585.0, 650.0}, // 7, 64-QAM 
		{78.0, 86.7, 162.0, 180, 351.0, 390.0, 702.0, 780.0}, // 8, 256-QAM
		{ 0.0,  0.0, 180.0, 200, 390.0, 433.3, 780.0, 866.7}, // 9, 256-QAM
		{ 0.0,  0.0,   0.0,   0,   0.0,     0,   0.0,     0}, // 10, 1024-QAM (non-standard)
		{ 0.0,  0.0,   0.0,   0,   0.0,     0,   0.0,     0} // 11, 1024-QAM (non-standard)
};

#endif // _VHT_RATE_H
