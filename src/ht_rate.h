#pragma once

#ifndef _HT_RATE_H
#define _HT_RATE_H

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


#endif // _HT_RATE_H