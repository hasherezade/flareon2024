#sudo pip install z3-solver

from z3 import *

PRINT_MIN = 0x20
PRINT_MAX = 0x7e

s = Solver()

x_0 = BitVec('x_0', 32)
x_1 = BitVec('x_1', 32)
x_2 = BitVec('x_2', 32)
x_3 = BitVec('x_3', 32)
x_4 = BitVec('x_4', 32)
x_5 = BitVec('x_5', 32)
x_6 = BitVec('x_6', 32)
x_7 = BitVec('x_7', 32)
x_8 = BitVec('x_8', 32)
x_9 = BitVec('x_9', 32)
x_10 = BitVec('x_10', 32)
x_11 = BitVec('x_11', 32)
x_12 = BitVec('x_12', 32)
x_13 = BitVec('x_13', 32)
x_14 = BitVec('x_14', 32)
x_15 = BitVec('x_15', 32)
x_16 = BitVec('x_16', 32)
x_17 = BitVec('x_17', 32)
x_18 = BitVec('x_18', 32)
x_19 = BitVec('x_19', 32)
x_20 = BitVec('x_20', 32)
x_21 = BitVec('x_21', 32)
x_22 = BitVec('x_22', 32)
x_23 = BitVec('x_23', 32)
x_24 = BitVec('x_24', 32)
x_25 = BitVec('x_25', 32)
x_26 = BitVec('x_26', 32)
x_27 = BitVec('x_27', 32)
x_28 = BitVec('x_28', 32)
x_29 = BitVec('x_29', 32)
x_30 = BitVec('x_30', 32)
x_31 = BitVec('x_31', 32)



s.add(x_0 > PRINT_MIN)
s.add(x_0 < PRINT_MAX)

s.add(x_1 > PRINT_MIN)
s.add(x_1 < PRINT_MAX)

s.add(x_2 > PRINT_MIN)
s.add(x_2 < PRINT_MAX)

s.add(x_3 > PRINT_MIN)
s.add(x_3 < PRINT_MAX)

s.add(x_4 > PRINT_MIN)
s.add(x_4 < PRINT_MAX)

s.add(x_5 > PRINT_MIN)
s.add(x_5 < PRINT_MAX)

s.add(x_6 > PRINT_MIN)
s.add(x_6 < PRINT_MAX)

s.add(x_7 > PRINT_MIN)
s.add(x_7 < PRINT_MAX)

s.add(x_8 > PRINT_MIN)
s.add(x_8 < PRINT_MAX)

s.add(x_9 > PRINT_MIN)
s.add(x_9 < PRINT_MAX)

s.add(x_10 > PRINT_MIN)
s.add(x_10 < PRINT_MAX)

s.add(x_11 > PRINT_MIN)
s.add(x_11 < PRINT_MAX)

s.add(x_12 > PRINT_MIN)
s.add(x_12 < PRINT_MAX)

s.add(x_13 > PRINT_MIN)
s.add(x_13 < PRINT_MAX)

s.add(x_14 > PRINT_MIN)
s.add(x_14 < PRINT_MAX)

s.add(x_15 > PRINT_MIN)
s.add(x_15 < PRINT_MAX)

s.add(x_16 > PRINT_MIN)
s.add(x_16 < PRINT_MAX)

s.add(x_17 > PRINT_MIN)
s.add(x_17 < PRINT_MAX)

s.add(x_18 > PRINT_MIN)
s.add(x_18 < PRINT_MAX)

s.add(x_19 > PRINT_MIN)
s.add(x_19 < PRINT_MAX)

s.add(x_20 > PRINT_MIN)
s.add(x_20 < PRINT_MAX)

s.add(x_21 > PRINT_MIN)
s.add(x_21 < PRINT_MAX)

s.add(x_22 > PRINT_MIN)
s.add(x_22 < PRINT_MAX)

s.add(x_23 > PRINT_MIN)
s.add(x_23 < PRINT_MAX)

s.add(x_24 > PRINT_MIN)
s.add(x_24 < PRINT_MAX)

s.add(x_25 > PRINT_MIN)
s.add(x_25 < PRINT_MAX)

s.add(x_26 > PRINT_MIN)
s.add(x_26 < PRINT_MAX)

s.add(x_27 > PRINT_MIN)
s.add(x_27 < PRINT_MAX)

s.add(x_28 > PRINT_MIN)
s.add(x_28 < PRINT_MAX)

s.add(x_29 > PRINT_MIN)
s.add(x_29 < PRINT_MAX)

s.add(x_30 > PRINT_MIN)
s.add(x_30 < PRINT_MAX)

s.add(x_31 > PRINT_MIN)
s.add(x_31 < PRINT_MAX)


res_0 = x_4  * 0xef7a8c
res_0 += 0x9d865d8d
res_0 -= x_24  * 0x45b53c
res_0 += 0x18baee57
res_0 -= x_0  * 0xe4cf8b
res_0 += 0x6ec04422
res_0 -= x_8  * 0xf5c990
res_0 += 0x6bfaa656
res_0 ^= x_20  * 0x733178
res_0 ^= 0x61e3db3b
res_0 ^= x_16  * 0x9a17b8
res_0 += 0x35d7fb4f
res_0 ^= x_12  * 0x773850
res_0 ^= 0x5a6f68be
res_0 ^= x_28  * 0xe21d3d
res_0 ^= 0x5C911D23
res_0 += 0x7E9B8587

s.add(res_0 == 0)

##

res_1 = x_17  * 0x99aa81
res_1 += 0x8b1215af
res_1 ^= x_5  * 0x4aba22
res_1 += 0x598015bf
res_1 ^= x_21  * 0x91a68a
res_1 ^= 0x6df18e52
res_1 ^= x_1  * 0x942fde
res_1 += 0x15c825ee
res_1 -= x_13  * 0xfe2fbe
res_1 += 0xd5682b64
res_1 -= x_29  * 0xd7e52f
res_1 += 0x798bd018
res_1 ^= x_25  * 0xe44f6a
res_1 += 0x1992adc2
res_1 += x_9  * 0xaf71d6
res_1 += 0xb0fc9725

s.add(res_1 == 0)

##

res_2 = x_10  * 0x48c500
res_2 += 0x70255e44
res_2 -= x_30  * 0x152887
res_2 += 0x65f04e48
res_2 -= x_14  * 0xaa4247
res_2 ^= 0x3d63ec69
res_2 ^= x_22  * 0x38d82d
res_2 ^= 0x872eca8f
res_2 ^= x_26  * 0xf120ac
res_2 += 0x803dbdcf
res_2 += x_2  * 0x254def
res_2 ^= 0xee380db3
res_2 ^= x_18  * 0x9ef3e7
res_2 += 0x921556f5
res_2 += x_6  * 0x69c573
res_2 += 0x42996496

s.add(res_2 == 0)

##

res_3 = x_11  * 0x67dda4
res_3 += 0xf4753afc
res_3 += x_31  * 0x5bb860
res_3 ^= 0xc1d47fc9
res_3 ^= x_23  * 0xab0ce5
res_3 += 0x544ff977
res_3 += x_7  * 0x148e94
res_3 += 0x634c1be7
res_3 -= x_15  * 0x9e06ae
res_3 += 0x5239df9c
res_3 ^= x_3  * 0xfb9de1
res_3 ^= 0x4e3633f7
res_3 -= x_27  * 0xa8a511
res_3 ^= 0xa61f9208
res_3 += x_19  * 0xd3468d
res_3 += 0x5af968a6

s.add(res_3 == 0)

##

res_4 = x_12  * 0x640ba9
res_4 += 0x516c7a5c
res_4 -= x_0  * 0xf1d9e5
res_4 += 0x8b424d6b
res_4 += x_28  * 0xd3e2f8
res_4 += 0x3802be78
res_4 += x_24  * 0xb558ce
res_4 += 0xccbe7372
res_4 -= x_8  * 0x2f03a7
res_4 ^= 0xe050b170
res_4 += x_16  * 0xb8fa61
res_4 ^= 0x1fc22df6
res_4 -= x_20  * 0xe0c507
res_4 ^= 0xd8376e57
res_4 += x_4  * 0x8e354e
res_4 += 0x2c4d3e78

s.add(res_4 == 0)

##

res_5 = x_17  * 0xa9b448
res_5 ^= 0x9f938499
res_5 += x_5  * 0x906550
res_5 += 0x407021af
res_5 ^= x_13  * 0xaa5ad2
res_5 ^= 0x77cf83a7
res_5 ^= x_29  * 0xc49349
res_5 ^= 0x3067f4e7
res_5 += x_9  * 0x314f8e
res_5 += 0xcd975f3b
res_5 ^= x_21  * 0x81968b
res_5 += 0x893d2e0b
res_5 -= x_25  * 0x5ffbac
res_5 ^= 0xf3378e3a
res_5 -= x_1  * 0xf63c8e
res_5 += 0x5583c348

s.add(res_5 == 0)

##

res_6 = x_22  * 0xa6edf9
res_6 ^= 0x77c58017
res_6 -= x_18  * 0xe87bf4
res_6 += 0x666428c0
res_6 -= x_2  * 0x19864d
res_6 += 0xbe77b413
res_6 += x_6  * 0x901524
res_6 ^= 0x247bf095
res_6 ^= x_10  * 0xc897cc
res_6 ^= 0xeff7eea8
res_6 ^= x_14  * 0x731197
res_6 += 0x67a0d262
res_6 += x_30  * 0x5f591c
res_6 += 0x316661f9
res_6 += x_26  * 0x579d0e
res_6 += 0x3bca9199

s.add(res_6 == 0)

##

res_7 = x_23  * 0x9afaf6
res_7 ^= 0xdb895413
res_7 += x_19  * 0x7d1a12
res_7 += 0x398603bc
res_7 += x_11  * 0x4d84b1
res_7 += 0xa30387dc
res_7 -= x_15  * 0x552b78
res_7 ^= 0xf54a725e
res_7 ^= x_7  * 0xf372a1
res_7 += 0xb3aefc53
res_7 += x_31  * 0xb40eb5
res_7 ^= 0x16fa70d2
res_7 ^= x_3  * 0x9e5c18
res_7 += 0x38784353
res_7 ^= x_27  * 0xf2513b
res_7 += 0xa02525e8

s.add(res_7 == 0)

##

res_8 = x_28  * 0xac70b9
res_8 += 0xdae0a932
res_8 ^= x_4  * 0xc42b6f
res_8 ^= 0xbc03104c
res_8 -= x_0  * 0x867193
res_8 += 0xdc48c63a
res_8 -= x_12  * 0x6d31fe
res_8 ^= 0x4baeb6d0
res_8 -= x_16  * 0xaaae58
res_8 += 0x328ede08
res_8 += x_20  * 0x9faa7a
res_8 += 0xbe0a2c9c
res_8 += x_24  * 0x354ac6
res_8 ^= 0xd8ad17f1
res_8 -= x_8  * 0x3f2acb
res_8 += 0x10d34ae4

s.add(res_8 == 0)

##

res_9 = x_29  * 0xe9d18a
res_9 ^= 0xcb5557ea
res_9 ^= x_25  * 0x8aa5b9
res_9 ^= 0x9125a906
res_9 -= x_17  * 0x241997
res_9 += 0x6e46fcb8
res_9 += x_5  * 0xe3da0f
res_9 += 0x442800ec
res_9 += x_13  * 0xa5f9eb
res_9 += 0xbde8f9af
res_9 += x_21  * 0xd6e0fb
res_9 += 0x36268dbd
res_9 += x_1  * 0x8dc36e
res_9 += 0xc54b7d21
res_9 ^= x_9  * 0xb072ee
res_9 += 0x16c50a64

s.add(res_9 == 0)

##

res_10 = x_30  * 0xd14f3e
res_10 ^= 0xa06c215b
res_10 -= x_26  * 0xc5ecbf
res_10 += 0xb197c5c0
res_10 ^= x_6  * 0x19ff9c
res_10 ^= 0x66e7d06c
res_10 += x_2  * 0xe3288b
res_10 ^= 0x80af4325
res_10 ^= x_10  * 0xcfb18c
res_10 += 0x1ec37c6d
res_10 ^= x_18  * 0xd208e5
res_10 += 0xf96d2b51
res_10 += x_14  * 0x42240f
res_10 += 0x78cdd8c3
res_10 -= x_22  * 0x1c6098
res_10 += 0x20ee254b

s.add(res_10 == 0)

res_11 = x_11  * 0x3768cc
res_11 ^= 0x19f61419
res_11 -= x_3  * 0x43be16
res_11 += 0x566cc6a8
res_11 ^= x_15  * 0xb7cca5
res_11 += 0x6db0599e
res_11 += x_27  * 0xf6419f
res_11 ^= 0xbd613538
res_11 ^= x_19  * 0xae52fc
res_11 += 0x717a44dd
res_11 -= x_23  * 0x5eeb81
res_11 += 0xdd02182d
res_11 ^= x_7  * 0xec1845
res_11 ^= 0xef8e5416
res_11 += x_31  * 0x61a3be
res_11 ^= 0x9288d4fa
res_11 += 0x7e4241fb

s.add(res_11 == 0)
##
res_12 = x_16  * 0x336e91
res_12 += 0xa1eb20e3
res_12 -= x_4  * 0xd45de9
res_12 += 0xc7e538e6
res_12 += x_8  * 0x76c8f8
res_12 ^= 0xd8caa2cd
res_12 -= x_20  * 0x945339
res_12 += 0x524d7efa
res_12 += x_12  * 0x4474ec
res_12 += 0x1b817d33
res_12 ^= x_0  * 0x51054f
res_12 ^= 0x3321c9b1
res_12 -= x_24  * 0xd7eb3b
res_12 += 0x36f6829d
res_12 -= x_28  * 0xad52e1
res_12 ^= 0x6ce2181a
res_12 += 0xc64bbbd

s.add(res_12 == 0)
##

res_13 = x_29  * 0x725059
res_13 ^= 0xa8b69f6b
res_13 += x_17  * 0x6dcfe7
res_13 ^= 0x653c249a
res_13 += x_1  * 0x8f4c44
res_13 ^= 0x68e87685
res_13 -= x_9  * 0xd2f4ce
res_13 += 0x78dc723b
res_13 ^= x_13  * 0xe99d3f
res_13 += 0xed16797a
res_13 += x_5  * 0xada536
res_13 += 0x6a5fa557
res_13 -= x_25  * 0xe0b352
res_13 ^= 0x43c00020
res_13 += x_21  * 0x8675b6
res_13 += 0x14892795

s.add(res_13 == 0)

##

res_14 = x_2  * 0x4a5e95
res_14 += 0x5ed7a1f1
res_14 += x_22  * 0x3a7b49
res_14 ^= 0x87a91310
res_14 -= x_6  * 0xf27038
res_14 ^= 0xf64a0f19
res_14 += x_30  * 0xa187d0
res_14 += 0x44338ca3
res_14 -= x_18  * 0xfc991a
res_14 ^= 0xf9ddd08f
res_14 -= x_26  * 0x4e947a
res_14 += 0xa656e8d2
res_14 ^= x_14  * 0x324ead
res_14 += 0x6965859c
res_14 -= x_10  * 0x656b1b
res_14 += 0xca35df7c

s.add(res_14 == 0)

##

res_15 = x_11  * 0x251b86
res_15 += 0xa751192c
res_15 -= x_7  * 0x743927
res_15 ^= 0xf851da43
res_15 ^= x_31  * 0x9a3479
res_15 ^= 0x335087a5
res_15 ^= x_3  * 0x778a0d
res_15 ^= 0x4bfd30d3
res_15 -= x_27  * 0x7e04b5
res_15 += 0xa2abfb6b
res_15 ^= x_19  * 0xf1c3ee
res_15 += 0x460c48a6
res_15 += x_15  * 0x883b8a
res_15 += 0x7b2ffbdc
res_15 += x_23  * 0x993db1
res_15 += 0x8782ac26

s.add(res_15 == 0)

##

res_16 = x_16  * 0xbae081
res_16 += 0x2359766f
res_16 ^= x_24  * 0xc2483b
res_16 += 0xea986a57
res_16 -= x_28  * 0x520ee2
res_16 ^= 0xa6ff8114
res_16 += x_8  * 0x9864ba
res_16 += 0x42833507
res_16 -= x_0  * 0x7cd278
res_16 ^= 0x360be811
res_16 ^= x_4  * 0xbe6605
res_16 += 0xb36d8573
res_16 += x_20  * 0x3bd2e8
res_16 += 0xb790cfd3
res_16 -= x_12  * 0x548c2b
res_16 += 0x8db7d3a

s.add(res_16 == 0)

##

res_17 = x_17  * 0xfb213b
res_17 += 0x988c29bd
res_17 ^= x_9  * 0xde6876
res_17 ^= 0x8649fde3
res_17 ^= x_29  * 0x629ff7
res_17 ^= 0xa0eeb203
res_17 -= x_25  * 0xdbb107
res_17 ^= 0x94aa6b62
res_17 -= x_1  * 0x262675
res_17 += 0x2030ab78
res_17 += x_5  * 0xd691c5
res_17 += 0xa4c118ba
res_17 -= x_13  * 0xcafc93
res_17 += 0xeee421de
res_17 -= x_21  * 0x81f945
res_17 += 0xcb2ed29

s.add(res_17 == 0)

##

res_18 = x_10  * 0x52f44d
res_18 ^= 0x33b3d0e4
res_18 ^= x_30  * 0xe6e66e
res_18 += 0xd8a28650
res_18 -= x_6  * 0xf98017
res_18 ^= 0x456e6c1d
res_18 -= x_14  * 0x34fcb0
res_18 ^= 0x28709cd8
res_18 ^= x_2  * 0x4d8ba9
res_18 += 0xb5482f53
res_18 ^= x_18  * 0x6c7e92
res_18 += 0x2af1d741
res_18 += x_22  * 0xa4711e
res_18 ^= 0x22e79af6
res_18 += x_26  * 0x33d374
res_18 += 0x5b07c064

s.add(res_18 == 0)

##

##

res_20 = x_24  * 0xb74a52
res_20 ^= 0x8354d4e8
res_20 ^= x_4  * 0xf22ecd
res_20 += 0xcb340dc5
res_20 += x_20  * 0xbef4be
res_20 ^= 0x60a6c39a
res_20 ^= x_8  * 0x7fe215
res_20 += 0xb14a7317
res_20 -= x_16  * 0xdb9f48
res_20 += 0x4356fa0e
res_20 -= x_28  * 0xbb4276
res_20 += 0x6df1ddb8
res_20 ^= x_0  * 0xa3fbef
res_20 += 0x4c22d2d3
res_20 ^= x_12  * 0xc5e883
res_20 ^= 0x50a6e5c9
res_20 += 0x271a423a

s.add(res_20 == 0)
##

res_21 = x_13  * 0x4b2d02
res_21 ^= 0x4b59b93a
res_21 -= x_9  * 0x84bb2c
res_21 ^= 0x42d5652c
res_21 ^= x_25  * 0x6f2d21
res_21 += 0x1020133a
res_21 += x_29  * 0x5fe38f
res_21 += 0x9d7f84e0
res_21 += x_21  * 0xea20a5
res_21 ^= 0x60779ceb
res_21 ^= x_17  * 0x5c17aa
res_21 ^= 0x1aaf8a2d
res_21 -= x_5  * 0xb9feb0
res_21 += 0x5241fd05
res_21 -= x_1  * 0x782f79
res_21 += 0xe7b16cc4

s.add(res_21 == 0)

##

res_22 = x_6  * 0x608d19
res_22 += 0xd1119d14
res_22 -= x_14  * 0xbe18f4
res_22 ^= 0xb86f9b72
res_22 ^= x_30  * 0x88dec9
res_22 += 0xaf5cd797
res_22 ^= x_18  * 0xb68150
res_22 += 0xc2f8c45b
res_22 += x_22  * 0x4d166c
res_22 += 0xbb1e1039
res_22 -= x_2  * 0x495e3f
res_22 += 0xe727b98e
res_22 -= x_10  * 0x5caba1
res_22 += 0xe5c3093f
res_22 += x_26  * 0x183a4d
res_22 += 0xcf77c502

s.add(res_22 == 0)


##


res_25 = x_1  * 0x73aaf0
res_25 ^= 0xa04e34f1
res_25 += x_29  * 0xf61e43
res_25 += 0xd09b66f3
res_25 += x_25  * 0x8cb5f0
res_25 += 0xc11c9b4b
res_25 ^= x_17  * 0x4f53a8
res_25 += 0x9b9a98d2
res_25 += x_9  * 0xb2e1fa
res_25 ^= 0x77c07fd8
res_25 -= x_21  * 0xb8b7b3
res_25 += 0x77d3eadf
res_25 += x_13  * 0x13b807
res_25 ^= 0x758dd142
res_25 ^= x_5  * 0xdd40c4
res_25 += 0xb0a9fde

s.add(res_25 == 0)

##

res_26 = x_14  * 0xca894b
res_26 += 0xa34fe406
res_26 += x_18  * 0x11552b
res_26 += 0x3764ecd4
res_26 ^= x_22  * 0x7dc36b
res_26 += 0xb45e777b
res_26 ^= x_26  * 0xcec5a6
res_26 ^= 0x2d59bc15
res_26 += x_30  * 0xb6e30d
res_26 ^= 0xfab9788c
res_26 ^= x_10  * 0x859c14
res_26 += 0x41868e54
res_26 += x_6  * 0xd178d3
res_26 += 0x958b0be3
res_26 ^= x_2  * 0x61645c
res_26 += 0x2247ff8d

s.add(res_26 == 0)

##

res_27 = x_27  * 0x7239e9
res_27 += 0x89f1a526
res_27 -= x_3  * 0xf1c3d1
res_27 += 0x10d75f98
res_27 ^= x_11  * 0x1b1367
res_27 ^= 0x31e00d5a
res_27 ^= x_19  * 0x8038b3
res_27 += 0xb5163447
res_27 += x_31  * 0x65fac9
res_27 += 0xe04a889a
res_27 -= x_23  * 0xd845ca
res_27 += 0x5482e3a8
res_27 += x_15  * 0xb2bbbc
res_27 ^= 0x3a017b92
res_27 ^= x_7  * 0x33c8bd
res_27 += 0xa31b6a50

s.add(res_27 == 0)

##

res_28 = x_0  * 0x53a4e0
res_28 += 0x9f9e7fc2
res_28 -= x_16  * 0x9bbfda
res_28 += 0x69b383f1
res_28 -= x_24  * 0x6b38aa
res_28 += 0x68ece860
res_28 += x_20  * 0x5d266f
res_28 += 0x5a4b0e60
res_28 -= x_8  * 0xedc3d3
res_28 ^= 0x93e59af6
res_28 -= x_4  * 0xb1f16c
res_28 ^= 0xe8d2b9a9
res_28 += x_12  * 0x1c8e5b
res_28 += 0x977c6d7d
res_28 += x_28  * 0x78f67b
res_28 += 0xbc17051a

s.add(res_28 == 0)

##

res_29 = x_17  * 0x87184c
res_29 += 0x8d5ea528
res_29 ^= x_25  * 0xf6372e
res_29 += 0x16ad4f89
res_29 -= x_21  * 0xd7355c
res_29 += 0x44df01cb
res_29 ^= x_5  * 0x471dc1
res_29 ^= 0x572c95f4
res_29 -= x_1  * 0x8c4d98
res_29 += 0x6b9af38c
res_29 -= x_13  * 0x5ceea1
res_29 ^= 0xf703dcc1
res_29 -= x_29  * 0xeb0863
res_29 += 0xad3bc09d
res_29 ^= x_9  * 0xb6227f
res_29 += 0x87f314d1

s.add(res_29 == 0)

##

res_30 = x_30  * 0x8c6412
res_30 ^= 0xc08c361c
res_30 ^= x_14  * 0xb253c4
res_30 += 0x21bb1147
res_30 += x_2  * 0x8f0579
res_30 += 0x596ee7a
res_30 -= x_22  * 0x7ac48a
res_30 += 0xbb787dd5
res_30 += x_10  * 0x2737e6
res_30 ^= 0xa2bb7683
res_30 -= x_18  * 0x4363b9
res_30 ^= 0x88c45378
res_30 ^= x_6  * 0xb38449
res_30 += 0xdf623f88
res_30 += x_26  * 0x6e1316
res_30 += 0x2fda49c2

s.add(res_30 == 0)

##

res_31 = x_19  * 0x390b78
res_31 += 0x7d5deea4
res_31 -= x_15  * 0x70e6c8
res_31 += 0x915cc61e
res_31 ^= x_27  * 0xd8a292
res_31 += 0xd772913b
res_31 -= x_23  * 0x978c71
res_31 += 0x1a27a128
res_31 += x_31  * 0x9a14d4
res_31 += 0x49698f34
res_31 ^= x_7  * 0x995144
res_31 += 0x2d188cbe
res_31 ^= x_11  * 0x811c39
res_31 += 0xd22fca9b
res_31 ^= x_3  * 0x9953d7
res_31 ^= 0x877669
res_31 += 0x86bddb88

s.add(res_31 == 0)
##

print(s)
# Create the constraints based on your equations

def parse_name(name):
    subs = 'x_'
    pos = name.find(subs)
    val = int(name[pos + len(subs):],10)
    return val

flag = {}
if s.check():
    print(s.model())
    for x in s.model():
        val = parse_name(x.name())
        flag[val] = s.model()[x].as_long()
        print("%s = %x  = %c" % ( x.name(), s.model()[x].as_long(), chr(s.model()[x].as_long()) ) )

keystr = ""
for x in range(0,32):
    if x in flag.keys():
        keystr += chr(flag[x])
    else:
        keystr += "_"
print(keystr)
