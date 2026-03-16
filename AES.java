/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.mycompany.passwordmanager;
import java.util.Arrays;
/**
 *
 * @author Zeina
 */
public class AES {
    private static final int Nb = 4; //number of columns in the state 
    private static final int Nk = 4;
    private static final int Nr = 10; //number of rounds as we using 128 bits 
    // s stands for the state(matrix) 
    private static final int[] Sbox = {
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
    };
    
    private static final int[] InvSbox = {
        0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
        0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
        0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
        0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
        0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
        0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
        0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
        0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
        0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
        0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
        0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
        0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
        0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
        0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
        0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
        0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
    };
     // //Rcon is the round cofficient in the g function 
     private static final int[] Rcon = {
        0x01000000,0x02000000,0x04000000,0x08000000,
        0x10000000,0x20000000,0x40000000,0x80000000,
        0x1B000000,0x36000000
    };
    private static int getSbox(int b) { return Sbox[b & 0xFF]; } //returns int 
    private static int getInvSbox(int b) { return InvSbox[b & 0xFF]; }
    //rotWord and subWord is the g function without the RC 
    private static int rotWord(int w) { 
        return ((w << 8) | ((w >>> 24) & 0xFF)) & 0xFFFFFFFF; }  // shift left by 8 bits | shift right by 24 bits
     // the ( | ) puts them back together 
    //getting the Vs through the S box before the round coffeients 
    // V1 V2 V3 V0
    private static int subWord(int w) {
        int b0 = getSbox((w >>> 24) & 0xFF);  //getting the MSB
        int b1 = getSbox((w >>> 16) & 0xFF); //second byte from the left
        int b2 = getSbox((w >>> 8) & 0xFF);
        int b3 = getSbox(w & 0xFF);  // LSB
        return ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) & 0xFFFFFFFF; //return it as it is combined 
      //| put or to combine them back into 32 bits.
    }
    private static int bytesToIntBE(byte[] b, int off) {
        if (off + 3 >= b.length) {
        System.out.println("ERROR: Array length=" + b.length + ", offset=" + off);
        System.out.println("Key must be 16 bytes for AES-128!");
        return 0; 
    }
        return ((b[off] & 0xFF) << 24) | ((b[off+1] & 0xFF) << 16) |
               ((b[off+2] & 0xFF) << 8) | (b[off+3] & 0xFF);
    }

    private static void intToBytesBE(int v, byte[] out, int off) {
        out[off] = (byte)((v >>> 24) & 0xFF);
        out[off+1] = (byte)((v >>> 16) & 0xFF);
        out[off+2] = (byte)((v >>> 8) & 0xFF);
        out[off+3] = (byte)(v & 0xFF);
    }

    //Key Schedule 
    public static int[] keyExpansion(byte[] key16) {
         if (key16.length != 16) {
        System.out.println("AES Error: Key must be 16 bytes, but got " + key16.length + " bytes");
        // Pad or truncate to 16 bytes
        byte[] paddedKey = Arrays.copyOf(key16, 16);
        return keyExpansion(paddedKey); // Recursively call with corrected key
    }
        int[] W = new int[Nb*(Nr+1)];
        for(int i=0;i<Nk;i++) W[i]=bytesToIntBE(key16,4*i);
        for(int i=Nk;i<W.length;i++){
            int temp=W[i-1];
            if(i%Nk==0) temp=subWord(rotWord(temp))^Rcon[i/Nk-1]; //making sure that iam making the RC at the MSB every 4 words 
            W[i]=W[i-Nk]^temp;  // to get word must XOR the one before it with the one before it by 4 words 
        }
        return W;
    }
    // r stands for rows , c is for columns 
   private static byte[][] bytesToState(byte[] in){
        byte[][] s=new byte[4][4]; int idx=0;
        for(int c=0;c<4;c++) for(int r=0;r<4;r++) s[r][c]=in[idx++];
        return s;
    }
    private static void stateToBytes(byte[][] s, byte[] out){
        int idx=0; for(int c=0;c<4;c++) for(int r=0;r<4;r++) out[idx++]=s[r][c];
    }
    private static void printState(String label, byte[][] s){
        System.out.println(label);
        for(int r=0;r<4;r++){
            for(int c=0;c<4;c++) System.out.printf("%02X ",s[r][c]);
            System.out.println();
        }
        System.out.println();
    }
    // (Byte): as to get it byte instead of int
     private static void subBytes(byte[][] s){ 
         for(int r=0;r<4;r++) for(int c=0;c<4;c++) s[r][c]=(byte)getSbox(s[r][c]&0xFF);} 
    private static void invSubBytes(byte[][] s){
        for(int r=0;r<4;r++) for(int c=0;c<4;c++) s[r][c]=(byte)getInvSbox(s[r][c]&0xFF);}
    private static void shiftRows(byte[][] s){
        for(int r=1;r<4;r++){                // no shifting in the first row
        byte[] tmp=new byte[4];              //new temp , new row shifting
        for(int c=0;c<4;c++) 
            tmp[c]=s[r][(c+r)%4];
        for(int c=0;c<4;c++)
            s[r][c]=tmp[c];  //copy tmp [] back to s[][]
        } 
    }
    private static void invShiftRows(byte[][] s){
        for(int r=1;r<4;r++){ byte[] tmp=new byte[4];  
        for(int c=0;c<4;c++) 
            tmp[(c+r)%4]=s[r][c];  // shifting right , tmp[0] = s[1][3]
        for(int c=0;c<4;c++) 
            s[r][c]=tmp[c]; } 
    }

    private static int xtime(int a){ //Multiplication a byte of a by x 
        a&=0xFF; 
        return ((a<<1)^((a&0x80)!=0?0x1B:0x00))&0xFF;  //x^8+x^4+x^3+x+1 = 1B , if MSB is 1 make a modular reduction
    }
    private static int mul(int a,int b){ //Multiply a by b in GF(2^8)usingxtime` and XOR
        int res=0; int aa=a&0xFF, bb=b&0xFF; 
        while(bb!=0){ //loop over each bit of b 
            if((bb&1)!=0) res^=aa;  //if b=1 XOR aa with res 
            aa=xtime(aa); 
            bb>>>=1;}  //move to the next bit of b 
        return res&0xFF;}
    private static void mixColumns(byte[][] s){
        for(int c=0;c<4;c++){ int a0=s[0][c]&0xFF,a1=s[1][c]&0xFF,a2=s[2][c]&0xFF,a3=s[3][c]&0xFF;
        s[0][c]=(byte)(mul(2,a0)^mul(3,a1)^a2^a3); // 02 03 01 01 
        s[1][c]=(byte)(a0^mul(2,a1)^mul(3,a2)^a3); // 01 02 03 01 
        s[2][c]=(byte)(a0^a1^mul(2,a2)^mul(3,a3));
        s[3][c]=(byte)(mul(3,a0)^a1^a2^mul(2,a3)); } }
    private static void invMixColumns(byte[][] s){
        for(int c=0;c<4;c++){
            int a0=s[0][c]&0xFF,a1=s[1][c]&0xFF,a2=s[2][c]&0xFF,a3=s[3][c]&0xFF;
        s[0][c]=(byte)(mul(0x0e,a0)^mul(0x0b,a1)^mul(0x0d,a2)^mul(0x09,a3)); //0E 0B 0D 09
        s[1][c]=(byte)(mul(0x09,a0)^mul(0x0e,a1)^mul(0x0b,a2)^mul(0x0d,a3)); // 09 0E 0B 0D 
        s[2][c]=(byte)(mul(0x0d,a0)^mul(0x09,a1)^mul(0x0e,a2)^mul(0x0b,a3)); 
        s[3][c]=(byte)(mul(0x0b,a0)^mul(0x0d,a1)^mul(0x09,a2)^mul(0x0e,a3)); } }

    private static void addRoundKey(byte[][] s,int[] w,int round){
        int start=round*Nb;
        for(int c=0;c<4;c++){ int word=w[start+c]; // 4 bytes of the round key
        s[0][c]^=(byte)((word>>>24)&0xFF);
        s[1][c]^=(byte)((word>>>16)&0xFF);
        s[2][c]^=(byte)((word>>>8)&0xFF);
        s[3][c]^=(byte)(word&0xFF);
        // XORing each byte of the state with each byte of the key 
        } }
public static byte[] encryptBlock(byte[] in16,byte[] key16,boolean verbose){
        int[] w=keyExpansion(key16); byte[][] s=bytesToState(in16);
        if(verbose) printState("Plaintext:",s); // if VERBOSE is ture the code prints every AES round step
        addRoundKey(s,w,0); if(verbose) printState("AddRoundKey(0):",s);
        for(int round=1;round<Nr;round++){
            subBytes(s); if(verbose) printState("SubBytes R"+round,s);
            shiftRows(s); if(verbose) printState("ShiftRows R"+round,s);
            mixColumns(s); if(verbose) printState("MixColumns R"+round,s);
            addRoundKey(s,w,round); if(verbose) printState("AddRoundKey R"+round,s);
        }
        subBytes(s); shiftRows(s); addRoundKey(s,w,Nr); //making the last round with no mix column
        if(verbose) printState("Ciphertext:",s);
        byte[] out=new byte[16];
        stateToBytes(s,out); return out;  // Converts AES 4 by 4 bytes into 16 bytes array
    }

    // --- Decryption ---
    public static byte[] decryptBlock(byte[] in16,byte[] key16,boolean verbose){
        int[] w=keyExpansion(key16); byte[][] s=bytesToState(in16);
        if(verbose) printState("Ciphertext:",s);
        addRoundKey(s,w,Nr);  //starting with the last round (10) 
        if(verbose) printState("AddRoundKey R"+Nr,s);
        for(int round=Nr-1;round>0;round--){
            invShiftRows(s); if(verbose) printState("InvShiftRows R"+round,s);
            invSubBytes(s); if(verbose) printState("InvSubBytes R"+round,s);
            addRoundKey(s,w,round); if(verbose) printState("AddRoundKey R"+round,s);
            invMixColumns(s); if(verbose) printState("InvMixColumns R"+round,s);
        }
        invShiftRows(s);
        invSubBytes(s);
        addRoundKey(s,w,0); 
        if(verbose) printState("Plaintext:",s);
        byte[] out=new byte[16]; 
        stateToBytes(s,out); return out;
    }
}
