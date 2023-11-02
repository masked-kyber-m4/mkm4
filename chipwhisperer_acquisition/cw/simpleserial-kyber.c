/*
	This file is part of the ChipWhisperer Example Targets
	Copyright (C) 2012-2017 NewAE Technology Inc.

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/



#include "hal.h"
#include <stdint.h>
#include <stdlib.h>
#include "simpleserial.h"
#include <string.h>

//Includes for this use case
#include "../common/randombytes.h"
#include "../crypto_kem/kyber768/m4/params.h"
#include "../crypto_kem/kyber768/m4/api.h"
#include "../crypto_kem/kyber768/m4/indcpa.h"
#include "../crypto_kem/kyber768/m4/masked.h"
#include "../crypto_kem/kyber768/m4/masked-poly.h"
#include "../crypto_kem/kyber768/m4/masked-cbd.h"
#include "../crypto_kem/kyber768/m4/cbd.h"
#include "../crypto_kem/kyber768/m4/poly.h"


uint8_t get_key(uint8_t* k, uint8_t len)
{
    return 0x00;
}

uint8_t get_pt(uint8_t* pt, uint8_t len)
{
    // value sent from Python stored in pt
    // array for storing the 8 values sent from Python
    uint16_t pt_value[8];

    // convert the 16 bytes of pt to 8 numbers
    for (int i = 0; i < 16; i++)
    {
        pt_value[i/2] = (pt_value[i/2] << 8) | pt[i];
    }

    poly ret;   // initialize to 0
    poly a;   // 0..3328 from pt
    poly b;   // 2649 317 2649 317...	
		
    trigger_high();
    poly_basemul(&ret, &a, &b); // call function here
    trigger_low();



    // send 16 bytes in pt back
    simpleserial_put('r', 16, pt);
    
    
    /* End user-specific code here. *
    ********************************/

    return 0x00;
}

uint8_t reset(uint8_t* x, uint8_t len)
{
    // Reset key here if needed
    return 0x00;
}

int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();

    /* Uncomment this to get a HELLO message for debug */

//	putch('h');
//	putch('e');
//	putch('l');
//	putch('l');
//	putch('o');
//	putch('\n');


    simpleserial_init();
    simpleserial_addcmd('k', 16, get_key);
    simpleserial_addcmd('p', 16, get_pt);
    simpleserial_addcmd('x', 0, reset);
    while (1){
        simpleserial_get();
    }

}

