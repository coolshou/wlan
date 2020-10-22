#pragma once

#ifndef _HT_RATE_H
#define _HT_RATE_H

const int DIV_HT = 8;
const double HT_MCSRate[12][4] = {
	// HT20, HT20 SGI, HT40, HT40 SGI
		{ 6.5,  7.2,  13.5,  15}, //0, BPSK
		{13.0, 14.4,  27.0,  30}, //1, 	QPSK 
		{19.5, 21.7,  40.5,  45}, //2, 	QPSK 
		{26.0, 28.9,  54.0,  60}, //3, 	16-QAM
		{39.0, 43.3,  81.0,  90}, //4, 	16-QAM
		{52.0, 57.8, 108.0, 120}, //5, 	64-QAM 
		{58.5, 65.0, 121.5, 135}, //6, 	64-QAM 
		{65.0, 72.2, 135.0, 150}, //7, 	64-QAM 
		// MCS8 => 2x2 mcs0
		//{78.0, 86.7, 162.0, 180}, //8, 	256-QAM  (non-standard)
		//{ 0.0,  0.0, 180.0, 200}, //9, 	256-QAM  (non-standard)
		//{ 0.0,  0.0, 202.5, 225}, //10,	1024-QAM  (non-standard)
		//{ 0.0,  0.0, 225.0, 250} //11, 	1024-QAM  (non-standard)
};


#endif // _HT_RATE_H
