#!/usr/bin/python3
#  ============================================================================
#  Name        : keygen.py
#  Author      : Hamza Megahed
#  Version     : 1.0
#  Copyright   : Copyright 2014 Hamza Megahed
#  Description : DES Key-Generator Algorithm
#  ============================================================================
#  
# 
#  ============================================================================
#    This file is part of DES Calculator.
# 
#     DES Calculator is free software: you can redistribute it and/or modify
#     it under the terms of the GNU General Public License as published by
#     the Free Software Foundation, either version 3 of the License, or
#     (at your option) any later version.
# 
#     DES Calculator is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.
# 
#     You should have received a copy of the GNU General Public License
#     along with DES Calculator.  If not, see <http://www.gnu.org/licenses/>.
#  ===========================================================================
print("\n\n");
print("\t***********************************");
print("\t**** Welcome to DES Calculator ****");
print("\t****** Author: Hamza Megahed ******");
print("\t***********************************");
# Convert key input from a Hex to binary
key_hexinput = input("Enter The Key in Hex(16 digits):\n")
try:
    (int(key_hexinput, 16)) 
except:
    print ("That is an invalid hex value")
if len(key_hexinput) == 16:    
        pass
else: raise ValueError('error')
key_bininput=bin(int(key_hexinput, 16))[2:].zfill(64)
k= []
k.append(0)
for digit in str(key_bininput):
    k.append(int(digit))

# C array
c=      [k[57],k[49],k[41],k[33],
         k[25],k[17],k[9], k[1],
         k[58],k[50],k[42],k[34],
         k[26],k[18],k[10],k[2],
         k[59],k[51],k[43],k[35],
         k[27],k[19],k[11],k[3],
         k[60],k[52],k[44],k[36]]
# D array
d=      [k[63],k[55],k[47],k[39],
         k[31],k[23],k[15],k[7],
         k[62],k[54],k[46],k[38],
         k[30],k[22],k[14],k[6],
         k[61],k[53],k[45],k[37],
         k[29],k[21],k[13],k[5],
         k[28],k[20],k[12],k[4]]

cd=c+d

shift = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
#------------------Key Generator For Encryption Algorithm-----------------
# Rotation Function
def rot(rot_num):

    global c, d
    c=c[shift[rot_num]:]+c[:shift[rot_num]]
    d=d[shift[rot_num]:]+d[:shift[rot_num]]
    cd=c+d 
    return (cd) 
key={}
pc2=[]

# Generator Function
def gen(x):
    key[str(x)]=rot(x)
    pc2=[key[str(x)][14-1],key[str(x)][17-1],key[str(x)][11-1],key[str(x)][24-1],key[str(x)][1-1],
         key[str(x)][5-1], key[str(x)][3-1], key[str(x)][28-1],key[str(x)][15-1],key[str(x)][6-1],
         key[str(x)][21-1],key[str(x)][10-1],key[str(x)][23-1],key[str(x)][19-1],key[str(x)][12-1],
         key[str(x)][4-1], key[str(x)][26-1],key[str(x)][8-1], key[str(x)][16-1],key[str(x)][7-1],
         key[str(x)][27-1],key[str(x)][20-1],key[str(x)][13-1],key[str(x)][2-1], key[str(x)][41-1],
         key[str(x)][52-1],key[str(x)][31-1],key[str(x)][37-1],key[str(x)][47-1],key[str(x)][55-1],
         key[str(x)][30-1],key[str(x)][40-1],key[str(x)][51-1],key[str(x)][45-1],key[str(x)][33-1],
         key[str(x)][48-1],key[str(x)][44-1],key[str(x)][49-1],key[str(x)][39-1],key[str(x)][56-1],
         key[str(x)][34-1],key[str(x)][53-1],key[str(x)][46-1],key[str(x)][42-1],key[str(x)][50-1],
         key[str(x)][36-1],key[str(x)][29-1],key[str(x)][32-1]]
    return pc2
#------------------Key Generator For Decryption Algorithm-----------------
# Rotation Array in Reverse
shiftd = [28, 27, 25, 23, 21, 19, 17, 15, 14, 12, 10, 8, 6, 4, 2, 1]

# Rotation Function 
def rot2(rot_num,c,d):
   
    c=c[shiftd[rot_num]:]+c[:shiftd[rot_num]]
    d=d[shiftd[rot_num]:]+d[:shiftd[rot_num]]
    cd=c+d 
    return (cd) 
key={}
pc2=[]
# Generator Function in Reverse
def gend(x):
    key[str(x)]=rot2(x,c,d)
    pc2=[key[str(x)][14-1],key[str(x)][17-1],key[str(x)][11-1],key[str(x)][24-1],key[str(x)][1-1],
         key[str(x)][5-1], key[str(x)][3-1], key[str(x)][28-1],key[str(x)][15-1],key[str(x)][6-1],
         key[str(x)][21-1],key[str(x)][10-1],key[str(x)][23-1],key[str(x)][19-1],key[str(x)][12-1],
         key[str(x)][4-1], key[str(x)][26-1],key[str(x)][8-1], key[str(x)][16-1],key[str(x)][7-1],
         key[str(x)][27-1],key[str(x)][20-1],key[str(x)][13-1],key[str(x)][2-1], key[str(x)][41-1],
         key[str(x)][52-1],key[str(x)][31-1],key[str(x)][37-1],key[str(x)][47-1],key[str(x)][55-1],
         key[str(x)][30-1],key[str(x)][40-1],key[str(x)][51-1],key[str(x)][45-1],key[str(x)][33-1],
         key[str(x)][48-1],key[str(x)][44-1],key[str(x)][49-1],key[str(x)][39-1],key[str(x)][56-1],
         key[str(x)][34-1],key[str(x)][53-1],key[str(x)][46-1],key[str(x)][42-1],key[str(x)][50-1],
         key[str(x)][36-1],key[str(x)][29-1],key[str(x)][32-1]]
    return pc2
