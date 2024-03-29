// 802.11ax (Wifi 6) High-Efficiency
#pragma once

#ifndef _HE_RATE_H
#define _HE_RATE_H

const int DIV_HE = 12;
const double HE_MCSRate[12][12] = {
	//20-0.8, 20-1.6, 20-3.2, 40-0.8, 40-1.6, 40-3.2, 80-0.8, 80-1.6, 80-3.2, 160-0.8, 160-1.6, 160-3.2, 
		{  8.6,   8.1,   7.3,  17.2,  16.3,  14.6,  36.0,  34.0,  30.6,   72.1,   68.1,   61.3}, //0, BPSK
		{ 17.2,  16.3,  14.6,  34.4,  32.5,  29.3,  72.1,  68.1,  61.3,  144.1,  136.1,  122.5}, //1
		{ 25.8,  24.4,  21.9,  51.6,  48.8,  43.9, 108.1, 102.1,  91.9,  216.2,  204.2,  183.8}, //2, QPSK
		{ 34.4,  32.5,  29.3,  68.8,  65.0,  58.5, 144.1, 136.1, 122.5,  288.2,  272.2,  245.0}, //3
		{ 51.6,  48.8,  43.9, 103.2,  97.5,  87.8, 216.2, 204.2, 183.8,  432.4,  408.3,  367.5}, //4, 16-QAM
		{ 68.8,  65.0,  58.5, 137.6, 130.0, 117.0, 288.2, 272.2, 245.0,  576.5,  544.4,  490.0}, //5
		{ 77.4,  73.1,  65.8, 154.9, 146.3, 131.6, 324.3, 306.3, 275.6,  648.5,  612.5,  551.3}, //6
		{ 86.0,  81.3,  73.1, 172.1, 162.5, 146.3, 360.3, 340.3, 306.3,  720.6,  680.6,  612.5}, //7, 64-QAM 
		{103.2,  97.5,  87.8, 206.5, 195.0, 175.5, 432.4, 408.3, 367.5,  864.7,  816.7,  735.0}, //8
		{114.7, 108.3,  97.5, 229.4, 216.7, 195.0, 480.4, 453.7, 408.3,  960.8,  907.4,  816.7}, //9, 256-QAM
		{129.0, 121.9, 109.7, 258.1, 243.8, 219.4, 540.4, 510.4, 459.4, 1080.9, 1020.8,  918.8}, //10
		{143.4, 135.4, 121.9, 286.8, 270.8, 243.8, 600.5, 567.1, 510.4, 1201.0, 1134.3, 1020.8} //11, 1024-QAM 
};

#endif // _HE_RATE_H
