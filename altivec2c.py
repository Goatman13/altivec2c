# altivec To C

FLT_CONVERSION_SUPPORT = 1
from ida_bytes import *
from idaapi import *
from idc import *
import idaapi
import ida_bytes
import idc

try:
	import numpy
except ImportError:
	FLT_CONVERSION_SUPPORT = 0
	warning("WARNING:\naltivec2c: numpy not found!\nFloat conversion opcodes unsupported!")

#Constants
MASK_ALLSET_128 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
MASK_ALLSET_96  = 0xFFFFFFFFFFFFFFFFFFFFFFFF
MASK_ALLSET_64  = 0xFFFFFFFFFFFFFFFF
MASK_ALLSET_32  = 0xFFFFFFFF
MASK_ALLSET_16  = 0xFFFF

def sign_extend_imm5(_8_16, value):

	if value & 0x10 == 0x10:
		value = (0xFFFFFFF0 | value & 0xF)
	else:
		value &= 0xF
	if _8_16 == 1:
		value &= 0xFF
	elif _8_16 == 2:
		value &= 0xFFFF
	return value

def imm5_to_signed_string(value):

	sign = ""
	imm = value & 0x1F
	if (imm > 0xF):
		imm = ~imm
		imm &= 0xF
		imm += 1
		sign = "-"
	return sign + "0x{:X}".format(imm)

def vaddcuw(vA, vB, vD):

	return "[4x32b] if v{:d} + v{:d} > 0xFFFFFFFF: v{:d} = 1, else v{:d} = 0".format(vA, vB, vD, vD)

#flt
def vaddfp(vA, vB, vD):

	return "[4xfloat] v{:d} = v{:d} + v{:d}".format(vD, vA, vB)

def vaddsbs(vA, vB, vD):

	return "v{:d}[16x8b][s] = v{:d} + v{:d}. if abs(v{:d}) > 0x7F: v{:d} = 0x7F | sign".format(vD, vA, vB, vD, vD)

def vaddshs(vA, vB, vD):

	return "v{:d}[8x16b][s] = v{:d} + v{:d}. if abs(v{:d}) > 0x7FFF: v{:d} = 0x7FFF | sign".format(vD, vA, vB, vD, vD)

def vaddsws(vA, vB, vD):

	return "v{:d}[4x32b][s] = v{:d} + v{:d}. if abs(v{:d}) > 0x7FFFFFFF: v{:d} = 0x7FFFFFFF | sign".format(vD, vA, vB, vD, vD)

# todo vaddubm
# todo vadduhm
# todo vadduwm

def vaddubs(vA, vB, vD):

	return "v{:d}[16x8b] = v{:d} + v{:d}. if v{:d} > 0xFF: v{:d} = 0xFF".format(vD, vA, vB, vD, vD)

def vadduhs(vA, vB, vD):

	return "v{:d}[8x16b] = v{:d} + v{:d}. if v{:d} > 0xFFFF: v{:d} = 0xFFFF".format(vD, vA, vB, vD, vD)

def vadduws(vA, vB, vD):

	return "v{:d}[4x32b] = v{:d} + v{:d}. if v{:d} > 0xFFFFFFFF: v{:d} = 0xFFFFFFFF".format(vD, vA, vB, vD, vD)

def vand(vA, vB, vD):

	return "v{:d}[128b] = v{:d} & v{:d}".format(vD, vA, vB)

def vandc(vA, vB, vD):

	return "v{:d}[128b] = v{:d} & ~v{:d}".format(vD, vA, vB)

def vavgsb(vA, vB, vD):

	return "v{:d}[16x8b][s] = (v{:d} + v{:d} + 1) >> 1 (sum before shift is 9 bits value)".format(vD, vA, vB)

def vavgsh(vA, vB, vD):

	return "v{:d}[8x16b][s] = (v{:d} + v{:d} + 1) >> 1 (sum before shift is 17 bits value)".format(vD, vA, vB)

def vavgsw(vA, vB, vD):

	return "v{:d}[4x32b][s] = (v{:d} + v{:d} + 1) >> 1 (sum before shift is 33 bits value)".format(vD, vA, vB)

def vavgub(vA, vB, vD):

	return "v{:d}[16x8b] = (v{:d} + v{:d} + 1) >> 1 (sum before shift is 9 bits value)".format(vD, vA, vB)

def vavguh(vA, vB, vD):

	return "v{:d}[8x16b] = (v{:d} + v{:d} + 1) >> 1 (sum before shift is 17 bits value)".format(vD, vA, vB)

def vavguw(vA, vB, vD):

	return "v{:d}[4x32b] = (v{:d} + v{:d} + 1) >> 1 (sum before shift is 33 bits value)".format(vD, vA, vB)

#todo verify cvts
def vcfsx(imm, vB, vD):

	imm    = numpy.exp2(imm)
	return "v{:d}[4xfloat] = (float)(s32)v{:d}  / {:.1f}".format(vD, vB, imm)

def vcfux(imm, vB, vD):

	imm    = numpy.exp2(imm)
	return "v{:d}[4xfloat] = (float)(u32)v{:d}  / {:.1f}".format(vD, vB, imm)

# flt
# todo
def vcmpbfp(vA, vB, vD, vRc):

	#if vRc == 1:
		#rc affected
	return ""

def vcmpeqfp(vA, vB, vD, vRc):

	cmt    = "[4xfloat] if v{:d} == v{:d}: v{:d} = 0xFFFFFFFF, else v{:d} = 0".format(vA, vB, vD, vD)
	if vRc == 1:
		cmt += " (affects CR6)"
	return cmt

def vcmpequb(vA, vB, vD, vRc):

	cmt    = "[16x8b] if v{:d} == v{:d}: v{:d} = 0xFF, else v{:d} = 0".format(vA, vB, vD, vD)
	if vRc == 1:
		cmt += " (affects CR6)"
	return cmt

def vcmpequh(vA, vB, vD, vRc):

	cmt    = "[8x16b] if v{:d} == v{:d}: v{:d} = 0xFFFF, else v{:d} = 0".format(vA, vB, vD, vD)
	if vRc == 1:
		cmt += " (affects CR6)"
	return cmt

def vcmpequw(vA, vB, vD, vRc):

	cmt    = "[4x32b] if v{:d} == v{:d}: v{:d} = 0xFFFFFFFF, else v{:d} = 0".format(vA, vB, vD, vD)
	if vRc == 1:
		cmt += " (affects CR6)"
	return cmt

def vcmpgefp(vA, vB, vD, vRc):

	cmt    = "[4xfloat] if v{:d} >= v{:d}: v{:d} = 0xFFFFFFFF, else v{:d} = 0".format(vA, vB, vD, vD)
	if vRc == 1:
		cmt += " (affects CR6)"
	return cmt
	
def vcmpgtfp(vA, vB, vD, vRc):

	cmt    = "[4xfloat] if v{:d} > v{:d}: v{:d} = 0xFFFFFFFF, else v{:d} = 0".format(vA, vB, vD, vD)
	if vRc == 1:
		cmt += " (affects CR6)"
	return cmt
	
def vcmpgtsb(vA, vB, vD, vRc):

	cmt    = "[16x8b][s] if v{:d} > v{:d}: v{:d} = 0xFF, else v{:d} = 0".format(vA, vB, vD, vD)
	if vRc == 1:
		cmt += " (affects CR6)"
	return cmt

def vcmpgtsh(vA, vB, vD, vRc):

	cmt    = "[8x16b][s] if v{:d} > v{:d}: v{:d} = 0xFFFF, else v{:d} = 0".format(vA, vB, vD, vD)
	if vRc == 1:
		cmt += " (affects CR6)"
	return cmt

def vcmpgtsw(vA, vB, vD, vRc):

	cmt    = "[4x32b][s] if v{:d} > v{:d}: v{:d} = 0xFFFFFFFF, else v{:d} = 0".format(vA, vB, vD, vD)
	if vRc == 1:
		cmt += " (affects CR6)"
	return cmt

def vcmpgtub(vA, vB, vD, vRc):

	cmt    = "[16x8b] if v{:d} > v{:d}: v{:d} = 0xFF, else v{:d} = 0".format(vA, vB, vD, vD)
	if vRc == 1:
		cmt += " (affects CR6)"
	return cmt

def vcmpgtuh(vA, vB, vD, vRc):

	cmt    = "[8x16b] if v{:d} > v{:d}: v{:d} = 0xFFFF, else v{:d} = 0".format(vA, vB, vD, vD)
	if vRc == 1:
		cmt += " (affects CR6)"
	return cmt

def vcmpgtuw(vA, vB, vD, vRc):

	cmt    = "[4x32b] if v{:d} > v{:d}: v{:d} = 0xFFFFFFFF, else v{:d} = 0".format(vA, vB, vD, vD)
	if vRc == 1:
		cmt += " (affects CR6)"
	return cmt

#todo verify cvts
def vctsxs(imm, vB, vD):

	imm    = numpy.exp2(imm)
	return "v{:d}[4x32b] = (s32)((float)v{:d}  * {:.1f})".format(vD, vB, imm)

def vctuxs(imm, vB, vD):

	imm    = numpy.exp2(imm)
	return "v{:d}[4x32b] = (u32)((float)v{:d}  * {:.1f})".format(vD, vB, imm)

def vlogefp(vB, vD):

	return "v{:d}[4xfloat] = log2(v{:d})".format(vD, vB)

def vexptefp(vB, vD):

	return "v{:d}[4xfloat] = exp2(v{:d})".format(vD, vB)

def vmaddfp(vA, vB, vC, vD):

	return "v{:d}[4xfloat] = (v{:d} * v{:d}) + v{:d}".format(vD, vA, vC, vB)

def vmaxfp(vA, vB, vD):

	return "[4xfloat] if v{:d} >= v{:d}: v{:d} = v{:d}, else v{:d} = v{:d}".format(vA, vB, vD, vA, vD, vB)

def vmaxsb(vA, vB, vD):

	return "[16x8b][s] if v{:d} >= v{:d}: v{:d} = v{:d}, else v{:d} = v{:d}".format(vA, vB, vD, vA, vD, vB)

def vmaxsh(vA, vB, vD):

	return "[8x16b][s] if v{:d} >= v{:d}: v{:d} = v{:d}, else v{:d} = v{:d}".format(vA, vB, vD, vA, vD, vB)

def vmaxsw(vA, vB, vD):

	return "[4x32b][s] if v{:d} >= v{:d}: v{:d} = v{:d}, else v{:d} = v{:d}".format(vA, vB, vD, vA, vD, vB)

def vmaxub(vA, vB, vD):

	return "[16x8b] if v{:d} >= v{:d}: v{:d} = v{:d}, else v{:d} = v{:d}".format(vA, vB, vD, vA, vD, vB)

def vmaxuh(vA, vB, vD):

	return "[8x16b] if v{:d} >= v{:d}: v{:d} = v{:d}, else v{:d} = v{:d}".format(vA, vB, vD, vA, vD, vB)

def vmaxuw(vA, vB, vD):

	return "[4x32b] if v{:d} >= v{:d}: v{:d} = v{:d}, else v{:d} = v{:d}".format(vA, vB, vD, vA, vD, vB)

def vmhaddshs(vA, vB, vC, vD):

	return "v{:d}[8x16b][s] = ((s32)(v{:d} * v{:d}) >> 16) + v{:d} if abs(v{:d}) > 0x7FFF: v{:d} = 0x7FFF | sign".format(vD, vA, vC, vB)

#todo check
def vmhraddshs(vA, vB, vC, vD):

	return "v{:d}[8x16b][s] = (((s32)(v{:d} * v{:d}) + 0x4000) >> 16) + v{:d} if abs(v{:d}) > 0x7FFF: v{:d} = 0x7FFF | sign".format(vD, vA, vC, vB)

def vminfp(vA, vB, vD):

	return "[4xfloat] if v{:d} < v{:d}: v{:d} = v{:d}, else v{:d} = v{:d}".format(vA, vB, vD, vA, vD, vB)

def vminsb(vA, vB, vD):

	return "[16x8b][s] if v{:d} < v{:d}: v{:d} = v{:d}, else v{:d} = v{:d}".format(vA, vB, vD, vA, vD, vB)

def vminsh(vA, vB, vD):

	return "[8x16b][s] if v{:d} < v{:d}: v{:d} = v{:d}, else v{:d} = v{:d}".format(vA, vB, vD, vA, vD, vB)

def vminsw(vA, vB, vD):

	return "[4x32b][s] if v{:d} < v{:d}: v{:d} = v{:d}, else v{:d} = v{:d}".format(vA, vB, vD, vA, vD, vB)

def vminub(vA, vB, vD):

	return "[16x8b] if v{:d} < v{:d}: v{:d} = v{:d}, else v{:d} = v{:d}".format(vA, vB, vD, vA, vD, vB)

def vminuh(vA, vB, vD):

	return "[8x16b] if v{:d} < v{:d}: v{:d} = v{:d}, else v{:d} = v{:d}".format(vA, vB, vD, vA, vD, vB)

def vminuw(vA, vB, vD):

	return "[4x32b] if v{:d} < v{:d}: v{:d} = v{:d}, else v{:d} = v{:d}".format(vA, vB, vD, vA, vD, vB)

# todo fixme
def vmladduhm(vA, vB, vC, vD):

	return "v{:d}[8x16b][s] = ((v{:d} * v{:d}) + v{:d}) & 0xFFFF".format(vD, vA, vB, vC)

def vmrghb(vA, vB, vD):

	cmt    = ".\n"
	cmt   += "v{:d}[0].byte  = v{:d}[0].byte\n".format(vD, vA)
	cmt   += "v{:d}[1].byte  = v{:d}[0].byte\n".format(vD, vB)
	cmt   += "v{:d}[2].byte  = v{:d}[1].byte\n".format(vD, vA)
	cmt   += "v{:d}[3].byte  = v{:d}[1].byte\n".format(vD, vB)
	cmt   += "v{:d}[4].byte  = v{:d}[2].byte\n".format(vD, vA)
	cmt   += "v{:d}[5].byte  = v{:d}[2].byte\n".format(vD, vB)
	cmt   += "v{:d}[6].byte  = v{:d}[3].byte\n".format(vD, vA)
	cmt   += "v{:d}[7].byte  = v{:d}[3].byte\n".format(vD, vB)
	cmt   += "v{:d}[8].byte  = v{:d}[4].byte\n".format(vD, vA)
	cmt   += "v{:d}[9].byte  = v{:d}[4].byte\n".format(vD, vB)
	cmt   += "v{:d}[10].byte = v{:d}[5].byte\n".format(vD, vA)
	cmt   += "v{:d}[11].byte = v{:d}[5].byte\n".format(vD, vB)
	cmt   += "v{:d}[12].byte = v{:d}[6].byte\n".format(vD, vA)
	cmt   += "v{:d}[13].byte = v{:d}[6].byte\n".format(vD, vB)
	cmt   += "v{:d}[14].byte = v{:d}[7].byte\n".format(vD, vA)
	cmt   += "v{:d}[15].byte = v{:d}[7].byte".format(vD, vB)
	return cmt

def vmrghh(vA, vB, vD):

	cmt    = ".\n"
	cmt   += "v{:d}[0].half = v{:d}[0].half\n".format(vD, vA)
	cmt   += "v{:d}[1].half = v{:d}[0].half\n".format(vD, vB)
	cmt   += "v{:d}[2].half = v{:d}[1].half\n".format(vD, vA)
	cmt   += "v{:d}[3].half = v{:d}[1].half\n".format(vD, vB)
	cmt   += "v{:d}[4].half = v{:d}[2].half\n".format(vD, vA)
	cmt   += "v{:d}[5].half = v{:d}[2].half\n".format(vD, vB)
	cmt   += "v{:d}[6].half = v{:d}[3].half\n".format(vD, vA)
	cmt   += "v{:d}[7].half = v{:d}[3].half".format(vD, vB)
	return cmt

def vmrghw(vA, vB, vD):

	cmt    = ".\n"
	cmt   += "v{:d}[0].word = v{:d}[0].word\n".format(vD, vA)
	cmt   += "v{:d}[1].word = v{:d}[0].word\n".format(vD, vB)
	cmt   += "v{:d}[2].word = v{:d}[1].word\n".format(vD, vA)
	cmt   += "v{:d}[3].word = v{:d}[1].word".format(vD, vB)
	return cmt

def vmrglb(vA, vB, vD):

	cmt    = ".\n"
	cmt   += "v{:d}[0].byte  = v{:d}[8].byte\n".format(vD, vA)
	cmt   += "v{:d}[1].byte  = v{:d}[8].byte\n".format(vD, vB)
	cmt   += "v{:d}[2].byte  = v{:d}[9].byte\n".format(vD, vA)
	cmt   += "v{:d}[3].byte  = v{:d}[9].byte\n".format(vD, vB)
	cmt   += "v{:d}[4].byte  = v{:d}[10].byte\n".format(vD, vA)
	cmt   += "v{:d}[5].byte  = v{:d}[10].byte\n".format(vD, vB)
	cmt   += "v{:d}[6].byte  = v{:d}[11].byte\n".format(vD, vA)
	cmt   += "v{:d}[7].byte  = v{:d}[11].byte\n".format(vD, vB)
	cmt   += "v{:d}[8].byte  = v{:d}[12].byte\n".format(vD, vA)
	cmt   += "v{:d}[9].byte  = v{:d}[12].byte\n".format(vD, vB)
	cmt   += "v{:d}[10].byte = v{:d}[13].byte\n".format(vD, vA)
	cmt   += "v{:d}[11].byte = v{:d}[13].byte\n".format(vD, vB)
	cmt   += "v{:d}[12].byte = v{:d}[14].byte\n".format(vD, vA)
	cmt   += "v{:d}[13].byte = v{:d}[14].byte\n".format(vD, vB)
	cmt   += "v{:d}[14].byte = v{:d}[15].byte\n".format(vD, vA)
	cmt   += "v{:d}[15].byte = v{:d}[15].byte".format(vD, vB)
	return cmt

def vmrglh(vA, vB, vD):

	cmt    = ".\n"
	cmt   += "v{:d}[0].half = v{:d}[4].half\n".format(vD, vA)
	cmt   += "v{:d}[1].half = v{:d}[4].half\n".format(vD, vB)
	cmt   += "v{:d}[2].half = v{:d}[5].half\n".format(vD, vA)
	cmt   += "v{:d}[3].half = v{:d}[5].half\n".format(vD, vB)
	cmt   += "v{:d}[4].half = v{:d}[6].half\n".format(vD, vA)
	cmt   += "v{:d}[5].half = v{:d}[6].half\n".format(vD, vB)
	cmt   += "v{:d}[6].half = v{:d}[7].half\n".format(vD, vA)
	cmt   += "v{:d}[7].half = v{:d}[7].half".format(vD, vB)
	return cmt

def vmrglw(vA, vB, vD):

	cmt    = ".\n"
	cmt   += "v{:d}[0].word  = v{:d}[2].word\n".format(vD, vA)
	cmt   += "v{:d}[1].word  = v{:d}[2].word\n".format(vD, vB)
	cmt   += "v{:d}[2].word  = v{:d}[3].word\n".format(vD, vA)
	cmt   += "v{:d}[3].word  = v{:d}[3].word".format(vD, vB)
	return cmt

# vmsummbm todo...

def vmulfp(vA, vB, vD):

	return "[4xfloat] v{:d} = v{:d} * v{:d}".format(vD, vA, vB)


def vmulesb(vA, vB, vD):

	cmt    = ".\nsigned\n"
	cmt  += "v{:d}[0].half = v{:d}[0].byte * v{:d}[0].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[1].half = v{:d}[2].byte * v{:d}[2].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[2].half = v{:d}[4].byte * v{:d}[4].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[3].half = v{:d}[6].byte * v{:d}[6].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[4].half = v{:d}[8].byte * v{:d}[8].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[5].half = v{:d}[10].byte * v{:d}[10].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[6].half = v{:d}[12].byte * v{:d}[12].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[7].half = v{:d}[14].byte * v{:d}[14].byte".format(vD, vA, vB)
	return cmt

def vmulesh(vA, vB, vD):

	cmt    = ".\nsigned\n"
	cmt  += "v{:d}[0].word = v{:d}[0].half * v{:d}[0].half\n".format(vD, vA, vB)
	cmt  += "v{:d}[1].word = v{:d}[2].half * v{:d}[2].half\n".format(vD, vA, vB)
	cmt  += "v{:d}[2].word = v{:d}[4].half * v{:d}[4].half\n".format(vD, vA, vB)
	cmt  += "v{:d}[3].word = v{:d}[6].half * v{:d}[6].half".format(vD, vA, vB)
	return cmt

def vmuleub(vA, vB, vD):

	cmt    = ".\n"
	cmt  += "v{:d}[0].half = v{:d}[0].byte * v{:d}[0].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[1].half = v{:d}[2].byte * v{:d}[2].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[2].half = v{:d}[4].byte * v{:d}[4].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[3].half = v{:d}[6].byte * v{:d}[6].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[4].half = v{:d}[8].byte * v{:d}[8].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[5].half = v{:d}[10].byte * v{:d}[10].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[6].half = v{:d}[12].byte * v{:d}[12].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[7].half = v{:d}[14].byte * v{:d}[14].byte".format(vD, vA, vB)
	return cmt

def vmuleuh(vA, vB, vD):

	cmt    = ".\n"
	cmt  += "v{:d}[0].word = v{:d}[0].half * v{:d}[0].half\n".format(vD, vA, vB)
	cmt  += "v{:d}[1].word = v{:d}[2].half * v{:d}[2].half\n".format(vD, vA, vB)
	cmt  += "v{:d}[2].word = v{:d}[4].half * v{:d}[4].half\n".format(vD, vA, vB)
	cmt  += "v{:d}[3].word = v{:d}[6].half * v{:d}[6].half".format(vD, vA, vB)
	return cmt

def vmulosb(vA, vB, vD):

	cmt    = ".\nsigned\n"
	cmt  += "v{:d}[0].half = v{:d}[1].byte * v{:d}[1].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[1].half = v{:d}[3].byte * v{:d}[3].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[2].half = v{:d}[5].byte * v{:d}[5].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[3].half = v{:d}[7].byte * v{:d}[7].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[4].half = v{:d}[9].byte * v{:d}[9].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[5].half = v{:d}[11].byte * v{:d}[11].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[6].half = v{:d}[13].byte * v{:d}[13].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[7].half = v{:d}[15].byte * v{:d}[15].byte".format(vD, vA, vB)
	return cmt

def vmulosh(vA, vB, vD):

	cmt    = ".\nsigned\n"
	cmt  += "v{:d}[0].word = v{:d}[1].half * v{:d}[1].half\n".format(vD, vA, vB)
	cmt  += "v{:d}[1].word = v{:d}[3].half * v{:d}[3].half\n".format(vD, vA, vB)
	cmt  += "v{:d}[2].word = v{:d}[5].half * v{:d}[5].half\n".format(vD, vA, vB)
	cmt  += "v{:d}[3].word = v{:d}[7].half * v{:d}[7].half".format(vD, vA, vB)
	return cmt

def vmuloub(vA, vB, vD):

	cmt    = ".\n"
	cmt  += "v{:d}[0].half = v{:d}[1].byte * v{:d}[1].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[1].half = v{:d}[3].byte * v{:d}[3].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[2].half = v{:d}[5].byte * v{:d}[5].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[3].half = v{:d}[7].byte * v{:d}[7].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[4].half = v{:d}[9].byte * v{:d}[9].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[5].half = v{:d}[11].byte * v{:d}[11].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[6].half = v{:d}[13].byte * v{:d}[13].byte\n".format(vD, vA, vB)
	cmt  += "v{:d}[7].half = v{:d}[15].byte * v{:d}[15].byte".format(vD, vA, vB)
	return cmt

def vmulouh(vA, vB, vD):

	cmt    = ".\n"
	cmt  += "v{:d}[0].word = v{:d}[1].half * v{:d}[1].half\n".format(vD, vA, vB)
	cmt  += "v{:d}[1].word = v{:d}[3].half * v{:d}[3].half\n".format(vD, vA, vB)
	cmt  += "v{:d}[2].word = v{:d}[5].half * v{:d}[5].half\n".format(vD, vA, vB)
	cmt  += "v{:d}[3].word = v{:d}[7].half * v{:d}[7].half".format(vD, vA, vB)
	return cmt

def vnmsubfp(vA, vB, vC, vD):

	return "v{:d}[4xfloat] = (v{:d} * v{:d}) - v{:d}".format(vD, vA, vC, vB)

def vnor(vA, vB, vD):

	return "v{:d}[4x32b] = ~(v{:d} | v{:d})".format(vD, vA, vB)

def vnot(vA, vD):

	return "v{:d}[4x32b] = ~v{:d}".format(vD, vA)

def vor(vA, vB, vD):

	return "v{:d}[4x32b] = v{:d} | v{:d}".format(vD, vA, vB)

def vmr(vA, vD):

	return "v{:d}[4x32b] = v{:d}".format(vD, vA)

def vperm(vA, vB, vC, vD):

	return ".\nfor (field = 0; field <= 15; field++)\n{{\n  x = v{:d}.byte[field]\n  if      (x & 0x10) == 0x00) {{v{:d}.byte[field] = v{:d}.byte[x & 0x0f];}}\n  else if (x & 0x10) == 0x10) {{v{:d}.byte[field] = v{:d}.byte[x & 0x0f];}}\n}}".format(vC, vD, vA, vD, vB)

def vpkpx(vA, vB, vD):

	cmt   = "temp  = (v{:d}[0-3].word >> 3) & 0x1F\n".format(vA)
	cmt  += "temp |= (v{:d}[0-3].word >> 6) & 0x3E0\n".format(vA)
	cmt  += "temp |= (v{:d}[0-3].word >> 9) & 0xFC00\n".format(vA)
	cmt  += "v{:d}[4x16b][0-3] = temp\n".format(vD)
	cmt  += "temp  = (v{:d}[0-3].word >> 3) & 0x1F\n".format(vB)
	cmt  += "temp |= (v{:d}[0-3].word >> 6) & 0x3E0\n".format(vB)
	cmt  += "temp |= (v{:d}[0-3].word >> 9) & 0xFC00\n".format(vB)
	cmt  += "v{:d}[4x16b][4-7] = temp".format(vD)
	return cmt

# todo pack opcodes

def vrefp(vD, vB):

	return "v{:d}[4xfloat] = 1.0 / v{:d}".format(vD, vB)

def vrfim(vD, vB):

	return "v{:d}[4xfloat] = RoundTowardNegativeInf(v{:d})".format(vD, vB)

def vrfin(vD, vB):

	return "v{:d}[4xfloat] = RoundTowardNearest(v{:d})".format(vD, vB)

def vrfip(vD, vB):

	return "v{:d}[4xfloat] = RoundTowardPositiveInf(v{:d})".format(vD, vB)

def vrfiz(vD, vB):

	return "v{:d}[4xfloat] = RoundTowardZero(v{:d})".format(vD, vB)

def vrlb(vD, vA, vB):

	return "v{:d}[16x8b] = rol8(v{:d}, (v{:d} & 7))".format(vD, vA, vB)

def vrlh(vD, vA, vB):

	return "v{:d}[8x16b] = rol16(v{:d}, (v{:d} & 0xF))".format(vD, vA, vB)

def vrlw(vD, vA, vB):

	return "v{:d}[4x32b] = rol32(v{:d}, (v{:d} & 0x1F))".format(vD, vA, vB)

def vrsqrtefp(vD, vB):

	return "v{:d}[4xfloat] = 1.0 / (v{:d} *  v{:d})".format(vD, vB, vB)

def vsel(vA, vB, vC, vD):

	return "[128b] if bit in v{:d} == 0 take bit from v{:d}, else take bit from v{:d}".format(vC, vA, vB)

def vsl(vD, vA, vB):

	return "v{:d}[128b] = v{:d} << (v{:d} & 7)".format(vD, vA, vB)

def vslb(vD, vA, vB):

	return "v{:d}[16x8b] = v{:d} << (v{:d} & 7)".format(vD, vA, vB)

def vsldoi(vD, vA, vB, sh):

	sh <<= 3
	shr  = 128 - sh
	return "v{:d}[128b] = (v{:d} << {:d}) | (v{:d} >> {:d})".format(vD, vA, sh, vB, shr)

def vslh(vD, vA, vB):

	return "v{:d}[8x16b] = v{:d} << (v{:d} & 0xF)".format(vD, vA, vB)

def vslo(vD, vA, vB):

	return "v{:d}[128b] = v{:d} << (v{:d} & 0x78)".format(vD, vA, vB)

def vslw(vD, vA, vB):

	return "v{:d}[4x32b] = v{:d} << (v{:d} & 0x1F)".format(vD, vA, vB)

def vspltb(vD, imm, vB):

	return "v{:d}[16x8b] = v{:d}[{:d}].byte".format(vD, vB, imm)

def vsplth(vD, imm, vB):
	
	imm &= 7
	return "v{:d}[8x16b] = v{:d}[{:d}].half".format(vD, vB, imm)

def vspltisb(vD, simm):

	neg = ""
	if simm > 0xF:
		neg = " ("
		neg += imm5_to_signed_string(simm)
		neg += ")"
	simm = sign_extend_imm5(1, simm)
	return "v{:d}[16x8b] = 0x{:02X}".format(vD, simm) + neg

def vspltish(vD, simm):

	neg = ""
	if simm > 0xF:
		neg = " ("
		neg += imm5_to_signed_string(simm)
		neg += ")"
	simm = sign_extend_imm5(2, simm)
	return "v{:d}[8x16b] = 0x{:04X}".format(vD, simm) + neg

def vspltisw(vD, simm):

	neg = ""
	if simm > 0xF:
		neg = " ("
		neg += imm5_to_signed_string(simm)
		neg += ")"
	simm = sign_extend_imm5(0, simm)
	return "v{:d}[4x32b] = 0x{:08X}".format(vD, simm) + neg

def vspltw(vD, imm, vB):
	
	imm &= 3
	return "v{:d}[4x32b] = v{:d}[{:d}].word".format(vD, vB, imm)

def vsr(vD, vA, vB):

	return "v{:d}[128b] = v{:d} >> (v{:d} & 7)".format(vD, vA, vB)

def vsrab(vD, vA, vB):

	return "v{:d}[16x8b][arithm] = v{:d} >> (v{:d} & 7)".format(vD, vA, vB)

def vsrah(vD, vA, vB):

	return "v{:d}[8x16b][arithm]= v{:d} >> (v{:d} & 0xF)".format(vD, vA, vB)

def vsraw(vD, vA, vB):

	return "v{:d}[4x32b][arithm] = v{:d} >> (v{:d} & 0x1F)".format(vD, vA, vB)

def vsrb(vD, vA, vB):

	return "v{:d}[16x8b] = v{:d} >> (v{:d} & 7)".format(vD, vA, vB)

def vsrh(vD, vA, vB):

	return "v{:d}[8x16b] = v{:d} >> (v{:d} & 0xF)".format(vD, vA, vB)

def vsro(vD, vA, vB):

	return "v{:d}[128b] = v{:d} >> (v{:d} & 0x78)".format(vD, vA, vB)

def vsrw(vD, vA, vB):

	return "v{:d}[4x32b] = v{:d} >> (v{:d} & 0x1F)".format(vD, vA, vB)




#VMX128
def vmaddfp128(vA, vB, vD):

	return "v{:d}[4xfloat] = (v{:d} * v{:d}) + v{:d}".format(vD, vA, vB, vD)

def vmaddcfp128(vA, vB, vD):

	return "v{:d}[4xfloat] = (v{:d} * v{:d}) + v{:d}".format(vD, vA, vD, vB)

def vnmsubfp128(vA, vB, vD):

	return "v{:d}[4xfloat] = (v{:d} * v{:d}) - v{:d}".format(vD, vA, vD, vB)

def vpermwi128(vPerm, vB, vD):

	z  = 0xAAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD
	sa = ((vPerm >> 6) & 3) * 32
	sb = ((vPerm >> 4) & 3) * 32
	sc = ((vPerm >> 2) & 3) * 32
	sd = ((vPerm >> 0) & 3) * 32
	a  = (z >> (96-sa)) & 0xFFFFFFFF
	b  = (z >> (96-sb)) & 0xFFFFFFFF
	c  = (z >> (96-sc)) & 0xFFFFFFFF
	d  = (z >> (96-sd)) & 0xFFFFFFFF
	return "v{:d}[128b] = v{:d}: {:08X}:{:08X}:{:08X}:{:08X}".format(vD,vB,a,b,c,d)

def vrlimi128(vD, vB, Imm ,Rot):

	# rotate
	z  = 0x0123
	z  = (z << (Rot * 4)) | (z << (16 - (Rot * 4)))
	za = (z >> 12) & 3
	zb = (z >>  8) & 3
	zc = (z >>  4) & 3
	zd = (z >>  0) & 3
	# mask
	a = (Imm >> 3) & 1
	b = (Imm >> 2) & 1
	c = (Imm >> 1) & 1
	d = (Imm >> 0) & 1
	# result
	result = ".\n"
	if a == 1:
		result += "v{:d}[0].word =  v{:d}[{:d}].word\n".format(vD,vB,za)
	else:
		result += "v{:d}[0].word =  v{:d}[0].word\n".format(vD,vD)
	if b == 1:
		result += "v{:d}[1].word =  v{:d}[{:d}].word\n".format(vD,vB,zb)
	else:
		result += "v{:d}[1].word =  v{:d}[1].word\n".format(vD,vD)
	if c == 1:
		result += "v{:d}[2].word =  v{:d}[{:d}].word\n".format(vD,vB,zc)
	else:
		result += "v{:d}[2].word =  v{:d}[2].word\n".format(vD,vD)
	if d == 1:
		result += "v{:d}[3].word =  v{:d}[{:d}].word".format(vD,vB,zd)
	else:
		result += "v{:d}[3].word =  v{:d}[3].word".format(vD,vD)
	return result


def altivecAsm2C(addr):

	opcode = get_wide_dword(addr)
	opcode_name = print_insn_mnem(addr)
	
	#Altivec
	vA     = (opcode >> 16) & 0x1F
	vB     = (opcode >> 11) & 0x1F
	vC     = (opcode >> 6 ) & 0x1F
	vD     = (opcode >> 21) & 0x1F
	vS     = (opcode >> 21) & 0x1F
	imm    = (opcode >> 16) & 0x1F
	simm   = (opcode >> 16) & 0x1F
	sh     = (opcode >> 6 ) & 0xF
	vRc    = (opcode >> 10) & 1

	#VMX128
	vmxA    = (opcode >> 16) & 0x1F | opcode & 0x20 | (opcode >> 4) & 0x40
	vmxB    = (opcode >> 11) & 0x1F | (opcode << 5) & 0x60
	vmxC    = (opcode >> 6)  & 0x7
	vmxD    = (opcode >> 21) & 0x1F | (opcode << 3) & 0x60
	vmxImm  = (opcode >> 16) & 0x1F
	vmxSimm = (opcode >> 16) & 0x1F
	vmxPerm = (opcode >> 16) & 0x1F | (opcode >> 1) & 0xE0
	vmxRc   = (opcode >> 6)  & 0x1
	vmxRot  = (opcode >> 6)  & 0x3
	vmxShb  = (opcode >> 6)  & 0xF



	if   opcode_name == "vaddcuw":       return vaddcuw(vA, vB, vD)
	elif opcode_name == "vaddfp":        return vaddfp(vA, vB, vD)
	elif opcode_name == "vaddsbs":       return vaddsbs(vA, vB, vD)
	elif opcode_name == "vaddshs":       return vaddshs(vA, vB, vD)
	elif opcode_name == "vaddsws":       return vaddsws(vA, vB, vD)
	elif opcode_name == "vaddubs":       return vaddubs(vA, vB, vD)
	elif opcode_name == "vadduhs":       return vadduhs(vA, vB, vD)
	elif opcode_name == "vadduws":       return vadduws(vA, vB, vD)
	elif opcode_name == "vand":          return vand(vA, vB, vD)
	elif opcode_name == "vandc":         return vandc(vA, vB, vD)
	elif opcode_name == "vavgsb":        return vavgsb(vA, vB, vD)
	elif opcode_name == "vavgsh":        return vavgsh(vA, vB, vD)
	elif opcode_name == "vavgsw":        return vavgsw(vA, vB, vD)
	elif opcode_name == "vavgub":        return vavgub(vA, vB, vD)
	elif opcode_name == "vavguh":        return vavguh(vA, vB, vD)
	elif opcode_name == "vavguw":        return vavguw(vA, vB, vD)
	elif opcode_name == "vcmpbfp":       return vcmpbfp(vA, vB, vD, vRc)
	elif opcode_name == "vcmpeqfp":      return vcmpeqfp(vA, vB, vD, vRc)
	elif opcode_name == "vcmpequb":      return vcmpequb(vA, vB, vD, vRc)
	elif opcode_name == "vcmpequh":      return vcmpequh(vA, vB, vD, vRc)
	elif opcode_name == "vcmpequw":      return vcmpequw(vA, vB, vD, vRc)
	elif opcode_name == "vcmpgefp":      return vcmpgefp(vA, vB, vD, vRc)
	elif opcode_name == "vcmpgtfp":      return vcmpgtfp(vA, vB, vD, vRc)
	elif opcode_name == "vcmpgtsb":      return vcmpgtsb(vA, vB, vD, vRc)
	elif opcode_name == "vcmpgtsh":      return vcmpgtsh(vA, vB, vD, vRc)
	elif opcode_name == "vcmpgtsw":      return vcmpgtsw(vA, vB, vD, vRc)
	elif opcode_name == "vcmpgtub":      return vcmpgtub(vA, vB, vD, vRc)
	elif opcode_name == "vcmpgtuh":      return vcmpgtuh(vA, vB, vD, vRc)
	elif opcode_name == "vcmpgtuw":      return vcmpgtuw(vA, vB, vD, vRc)
	elif opcode_name == "vcmpbfp.":      return vcmpbfp(vA, vB, vD, vRc)
	elif opcode_name == "vcmpeqfp.":     return vcmpeqfp(vA, vB, vD, vRc)
	elif opcode_name == "vcmpequb.":     return vcmpequb(vA, vB, vD, vRc)
	elif opcode_name == "vcmpequh.":     return vcmpequh(vA, vB, vD, vRc)
	elif opcode_name == "vcmpequw.":     return vcmpequw(vA, vB, vD, vRc)
	elif opcode_name == "vcmpgefp.":     return vcmpgefp(vA, vB, vD, vRc)
	elif opcode_name == "vcmpgtfp.":     return vcmpgtfp(vA, vB, vD, vRc)
	elif opcode_name == "vcmpgtsb.":     return vcmpgtsb(vA, vB, vD, vRc)
	elif opcode_name == "vcmpgtsh.":     return vcmpgtsh(vA, vB, vD, vRc)
	elif opcode_name == "vcmpgtsw.":     return vcmpgtsw(vA, vB, vD, vRc)
	elif opcode_name == "vcmpgtub.":     return vcmpgtub(vA, vB, vD, vRc)
	elif opcode_name == "vcmpgtuh.":     return vcmpgtuh(vA, vB, vD, vRc)
	elif opcode_name == "vcmpgtuw.":     return vcmpgtuw(vA, vB, vD, vRc)
	elif opcode_name == "vlogefp":       return vlogefp(vB, vD)
	elif opcode_name == "vexptefp":      return vexptefp(vB, vD)
	elif opcode_name == "vmaddfp":       return vmaddfp(vA, vB, vC, vD)
	elif opcode_name == "vmaxfp":        return vmaxfp(vA, vB, vD)
	elif opcode_name == "vmaxsb":        return vmaxsb(vA, vB, vD)
	elif opcode_name == "vmaxsh":        return vmaxsh(vA, vB, vD)
	elif opcode_name == "vmaxsw":        return vmaxsw(vA, vB, vD)
	elif opcode_name == "vmaxub":        return vmaxub(vA, vB, vD)
	elif opcode_name == "vmaxuh":        return vmaxuh(vA, vB, vD)
	elif opcode_name == "vmaxuw":        return vmaxuw(vA, vB, vD)
	elif opcode_name == "vmhaddshs":     return vmhaddshs(vA, vB, vC, vD)
	elif opcode_name == "vmhraddshs":    return vmhraddshs(vA, vB, vC, vD)
	elif opcode_name == "vminfp":        return vminfp(vA, vB, vD)
	elif opcode_name == "vminsb":        return vminsb(vA, vB, vD)
	elif opcode_name == "vminsh":        return vminsh(vA, vB, vD)
	elif opcode_name == "vminsw":        return vminsw(vA, vB, vD)
	elif opcode_name == "vminub":        return vminub(vA, vB, vD)
	elif opcode_name == "vminuh":        return vminuh(vA, vB, vD)
	elif opcode_name == "vminuw":        return vminuw(vA, vB, vD)
	elif opcode_name == "vmladduhm":     return vmladduhm(vA, vB, vC, vD)
	elif opcode_name == "vmrghb":        return vmrghb(vA, vB, vD)
	elif opcode_name == "vmrghh":        return vmrghh(vA, vB, vD)
	elif opcode_name == "vmrghw":        return vmrghw(vA, vB, vD)
	elif opcode_name == "vmrglb":        return vmrglb(vA, vB, vD)
	elif opcode_name == "vmrglh":        return vmrglh(vA, vB, vD)
	elif opcode_name == "vmrglw":        return vmrglw(vA, vB, vD)
	elif opcode_name == "vmulfp":        return vmulfp(vA, vB, vD)
	elif opcode_name == "vmulesb":       return vmulesb(vA, vB, vD)
	elif opcode_name == "vmulesh":       return vmulesh(vA, vB, vD)
	elif opcode_name == "vmuleub":       return vmuleub(vA, vB, vD)
	elif opcode_name == "vmuleuh":       return vmuleuh(vA, vB, vD)
	elif opcode_name == "vmulosb":       return vmulosb(vA, vB, vD)
	elif opcode_name == "vmulosh":       return vmulosh(vA, vB, vD)
	elif opcode_name == "vmuloub":       return vmuloub(vA, vB, vD)
	elif opcode_name == "vmulouh":       return vmulouh(vA, vB, vD)
	elif opcode_name == "vnmsubfp":      return vnmsubfp(vA, vB, vC, vD)
	elif opcode_name == "vnor":          return vnor(vA, vB, vD)
	elif opcode_name == "vnot":          return vnot(vA, vD)
	elif opcode_name == "vor":           return vor(vA, vB, vD)
	elif opcode_name == "vmr":           return vmr(vA, vD)
	elif opcode_name == "vperm":         return vperm(vA, vB, vC, vD)	
	elif opcode_name == "vpkpx":         return vpkpx(vA, vB, vD)
	elif opcode_name == "vrefp":         return vrefp(vD, vB)
	elif opcode_name == "vrfim":         return vrfim(vD, vB)
	elif opcode_name == "vrfin":         return vrfin(vD, vB)
	elif opcode_name == "vrfip":         return vrfip(vD, vB)
	elif opcode_name == "vrfiz":         return vrfiz(vD, vB)
	elif opcode_name == "vrlb":          return vrlb(vD, vA, vB)
	elif opcode_name == "vrlh":          return vrlh(vD, vA, vB)
	elif opcode_name == "vrlw":          return vrlw(vD, vA, vB)
	elif opcode_name == "vrsqrtefp":     return vrsqrtefp(vD, vB)
	elif opcode_name == "vsel":          return vsel(vA, vB, vC, vD)
	elif opcode_name == "vsl":           return vsl(vD, vA, vB)
	elif opcode_name == "vslb":          return vslb(vD, vA, vB)
	elif opcode_name == "vsldoi":        return vsldoi(vD, vA, vB, sh)
	elif opcode_name == "vslh":          return vslh(vD, vA, vB)
	elif opcode_name == "vslo":          return vslo(vD, vA, vB)
	elif opcode_name == "vslw":          return vslw(vD, vA, vB)
	elif opcode_name == "vspltb":        return vspltb(vD, imm, vB)
	elif opcode_name == "vsplth":        return vsplth(vD, imm, vB)
	elif opcode_name == "vspltisb":      return vspltisb(vD, simm)
	elif opcode_name == "vspltish":      return vspltish(vD, simm)
	elif opcode_name == "vspltisw":      return vspltisw(vD, simm)
	elif opcode_name == "vspltw":        return vspltw(vD, imm, vB)
	elif opcode_name == "vsr":           return vsr(vD, vA, vB)
	elif opcode_name == "vsrab":         return vsrab(vD, vA, vB)
	elif opcode_name == "vsrah":         return vsrah(vD, vA, vB)
	elif opcode_name == "vsraw":         return vsraw(vD, vA, vB)
	elif opcode_name == "vsrb":          return vsrb(vD, vA, vB)
	elif opcode_name == "vsrh":          return vsrh(vD, vA, vB)
	elif opcode_name == "vsro":          return vsro(vD, vA, vB)
	elif opcode_name == "vsrw":          return vsrw(vD, vA, vB)	
	#VMX128
	elif opcode_name == "vaddfp128":     return vaddfp(vmxA, vmxB, vmxD)
	elif opcode_name == "vand128":       return vand(vmxA, vmxB, vmxD)
	elif opcode_name == "vandc128":      return vandc(vmxA, vmxB, vmxD)
	elif opcode_name == "vcmpeqfp128":   return vcmpeqfp(vmxA, vmxB, vmxD, vmxRc)
	elif opcode_name == "vcmpeqfp128.":  return vcmpeqfp(vmxA, vmxB, vmxD, vmxRc)
	elif opcode_name == "vcmpequw128":   return vcmpequw(vmxA, vmxB, vmxD, vmxRc)
	elif opcode_name == "vcmpequw128.":  return vcmpequw(vmxA, vmxB, vmxD, vmxRc)
	elif opcode_name == "vcmpgefp128":   return vcmpgefp(vmxA, vmxB, vmxD, vmxRc)
	elif opcode_name == "vcmpgefp128.":  return vcmpgefp(vmxA, vmxB, vmxD, vmxRc)
	elif opcode_name == "vcmpgtfp128":   return vcmpgtfp(vmxA, vmxB, vmxD, vmxRc)
	elif opcode_name == "vcmpgtfp128.":  return vcmpgtfp(vmxA, vmxB, vmxD, vmxRc)
	elif opcode_name == "vlogefp128":    return vlogefp(vmxB, vmxD)
	elif opcode_name == "vexptefp128":   return vexptefp(vmxB, vmxD)
	elif opcode_name == "vmaddcfp128":   return vmaddfp128(vmxA, vmxB, vmxD)
	elif opcode_name == "vmaddfp128":    return vmaddcfp128(vmxA, vmxB, vmxD)
	elif opcode_name == "vmaxfp128":     return vmaxfp(vmxA, vmxB, vmxD)
	elif opcode_name == "vminfp128":     return vminfp(vmxA, vmxB, vmxD)
	elif opcode_name == "vmrghw128":     return vmrghw(vmxA, vmxB, vmxD)
	elif opcode_name == "vmrglw128":     return vmrglw(vmxA, vmxB, vmxD)
	elif opcode_name == "vmulfp128":     return vmulfp(vA, vB, vD)
	elif opcode_name == "vnmsubfp128":   return vnmsubfp128(vmxA, vmxB, vmxD)
	elif opcode_name == "vnor128":       return vnor(vmxA, vmxB, vmxD)
	elif opcode_name == "vnot128":       return vnot(vmxA, vmxD)
	elif opcode_name == "vor128":        return vor(vmxA, vmxB, vmxD)
	elif opcode_name == "vmr128":        return vmr(vmxA, vmxD)
	elif opcode_name == "vperm128":      return vperm(vmxA, vmxB, vmxC, vmxD)
	elif opcode_name == "vpermwi128":    return vpermwi128(vmxPerm, vmxB, vmxD)
	elif opcode_name == "vrefp128":      return vrefp(vmxD, vmxB)
	elif opcode_name == "vrfim128":      return vrfim(vmxD, vmxB)
	elif opcode_name == "vrfin128":      return vrfin(vmxD, vmxB)
	elif opcode_name == "vrfip128":      return vrfip(vmxD, vmxB)
	elif opcode_name == "vrfiz128":      return vrfiz(vmxD, vmxB)
	elif opcode_name == "vrlw128":       return vrlw(vmxD, vmxA, vmxB)
	elif opcode_name == "vrlimi128":     return vrlimi128(vmxD, vmxB, vmxImm ,vmxRot)
	elif opcode_name == "vrsqrtefp128":  return vrsqrtefp(vmxD, vmxB)
	elif opcode_name == "vsldoi128":     return vsldoi(vmxD, vmxA, vmxB, vmxShb)
	elif opcode_name == "vslw128":       return vslw(vmxD, vmxA, vmxB)
	elif opcode_name == "vspltisw128":   return vspltisw(vmxD, vmxSimm)
	elif opcode_name == "vspltw128":     return vspltw(vmxD, vmxImm, vmxB)

	# Use numpy
	elif opcode_name == "vcfsx" and FLT_CONVERSION_SUPPORT:      return vcfsx(imm, vB, vD)
	elif opcode_name == "vcfux" and FLT_CONVERSION_SUPPORT:      return vcfux(imm, vB, vD)
	elif opcode_name == "vctsxs" and FLT_CONVERSION_SUPPORT:     return vctsxs(imm, vB, vD)
	elif opcode_name == "vctuxs" and FLT_CONVERSION_SUPPORT:     return vctuxs(imm, vB, vD)
	elif opcode_name == "vcsxwfp128" and FLT_CONVERSION_SUPPORT: return vcfsx(vmxSimm, vmxB, vmxD) # correct?
	elif opcode_name == "vcuxwfp128" and FLT_CONVERSION_SUPPORT: return vcfux(vmxImm, vmxB, vmxD) # correct?

	return 0

def run_task(start_addr, end_addr, always_insert_comment):

	# convert all instructions within the bounds
	addr = start_addr
	while(addr < end_addr):
		print_str = altivecAsm2C(addr)
		if(print_str != 0 and print_str != 1):
			set_cmt(addr, print_str, False)
		elif (print_str == 0 and always_insert_comment == True):
			msg("0x{:X}: Error converting altivec to C code\n".format(addr))
		addr += 4

def PluginMain():

	# select current line or selected lines
	always_insert_comment = False
	start_addr = read_selection_start()
	end_addr = read_selection_end()
	if(start_addr == BADADDR):
		start_addr = get_screen_ea();
		end_addr = start_addr + 4;
		always_insert_comment = True

	run_task(start_addr, end_addr, always_insert_comment)


def PluginMainF():

	# convert current function
	p_func = get_func(get_screen_ea());
	if(p_func == None):
		msg("Not in a function, so can't do altivec to C conversion for the current function!\n");
		return;
	start_addr = p_func.start_ea;
	end_addr = p_func.end_ea;
	always_insert_comment = False;

	run_task(start_addr, end_addr, always_insert_comment)


#/***************************************************************************************************
#*
#*	Strings required for IDA Pro's PLUGIN descriptor block
#*
#***************************************************************************************************/
#
G_PLUGIN_COMMENT = "Altivec To C Conversion Assist"
G_PLUGIN_HELP = "This plugin assists in converting altivec instructions into their relevant C code.\nIt is especially useful for the tricky bit manipulation and shift instructions.\n"
G_PLUGIN_NAME = "Altivec To C: Selected Lines"

#/***************************************************************************************************
#*
#*	This 'PLUGIN' data block is how IDA Pro interfaces with this plugin.
#*
#***************************************************************************************************/

class ActionHandler(idaapi.action_handler_t):

    def __init__(self, callback):

        idaapi.action_handler_t.__init__(self)
        self.callback = callback

    def activate(self, ctx):

        self.callback()
        return 1

    def update(self, ctx):

        return idaapi.AST_ENABLE_ALWAYS

def register_actions():

    actions = [
        {
            'id': 'start:a2c',
            'name': G_PLUGIN_NAME,
            'hotkey': 'F3',
            'comment': G_PLUGIN_COMMENT,
            'callback': PluginMain,
            'menu_location': 'Start a2c'
        },
        {
            'id': 'start:a2c1',
            'name': 'altivec2c unimplemented',
            'hotkey': 'Alt-Shift-F3',
            'comment': G_PLUGIN_COMMENT,
            'callback': PluginMainF,
            'menu_location': 'Start a2c1'
        }
    ]

    for action in actions:

        if not idaapi.register_action(idaapi.action_desc_t(
            action['id'], # Must be the unique item
            action['name'], # The name the user sees
            ActionHandler(action['callback']), # The function to call
            action['hotkey'], # A shortcut, if any (optional)
            action['comment'] # A comment, if any (optional)
        )):

            print('Failed to register ' + action['id'])

        if not idaapi.attach_action_to_menu(
            action['menu_location'], # The menu location
            action['id'], # The unique function ID
            0):

            print('Failed to attach to menu '+ action['id'])

class altivec_helper_t(idaapi.plugin_t):
	flags = idaapi.PLUGIN_HIDE
	comment = G_PLUGIN_COMMENT
	help = G_PLUGIN_HELP
	wanted_name = G_PLUGIN_NAME
	wanted_hotkey = "F3"

	def init(self):
		if (idaapi.ph.id == idaapi.PLFM_PPC):
			register_actions()
			idaapi.msg("altivec2c: loaded\n")
			return idaapi.PLUGIN_KEEP

		return idaapi.PLUGIN_SKIP

	def run(self, arg):
		idaapi.msg("altivec2c: run\n")

	def term(self):
		pass

def PLUGIN_ENTRY():
	return altivec_helper_t()
