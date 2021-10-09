#pragma once

// bootloaders
typedef enum {
    CA_1BL = 0x0342,
	CB_2BL = 0x4342,
	CC_3BL = 0x4343,
	CD_4BL = 0x4344,
	CE_5BL = 0x4345,
	CF_6BL = 0x4346,
	CG_7BL = 0x4347,
	SB_2BL = 0x5342,
	SC_3BL = 0x5343,
	SD_4BL = 0x5344,
	SE_5BL = 0x5345,
	SF_6BL = 0x5346,
	SG_7BL = 0x5347
} BLMagic;

// XeKeys
typedef enum {
	PeekBYTE  = 0,
	PeekWORD  = 1,
	PeekDWORD = 2,
	PeekQWORD = 3,
	PeekBytes = 4,
	PokeBYTE  = 5,
	PokeWORD  = 6,
	PokeDWORD = 7,
	PokeQWORD = 8,
	PokeBytes = 9,
	PeekSPR   = 0xA,
	HvExecute = 0xC
} HVPPCommand;