// AESencrypt: AES encryption
import java.util.*;
import java.io.*;

class AESencrypt {
   private final int Nb = 4; // words in a block, always 4 for now
   private int Nk; // key length in words
   private int Nr; // number of rounds, = Nk + 6
   private int wCount; // position in w for RoundKey (= 0 each encrypt)
   private AEStables tab; // all the tables needed for AES
   private byte[] w; // the expanded key

   // AESencrypt: constructor for class.  Mainly expands key
   public AESencrypt(byte[] key, int NkIn) {
      Nk = NkIn; // words in a key, = 4, or 6, or 8
      Nr = Nk + 6; // corresponding number of rounds
      tab = new AEStables(); // class to give values of various functions
      w = new byte[4*Nb*(Nr+1)]; // room for expanded key
      KeyExpansion(key, w); // length of w depends on Nr
   }
   
   // Cipher: actual AES encrytion
   public void Cipher(byte[] in, byte[] out) {
      wCount = 0; // count bytes in expanded key throughout encryption
      byte[][] state = new byte[4][Nb]; // the state array
      Copy.copy(state, in); // actual component-wise copy
      AddRoundKey(state); // xor with expanded key
      for (int round = 1; round < Nr; round++) {
         Print.printArray("Start round  " + round + ":", state);
         SubBytes(state); // S-box substitution
         ShiftRows(state); // mix up rows
         MixColumns(state); // complicated mix of columns
         AddRoundKey(state); // xor with expanded key
      }
      Print.printArray("Start round " + Nr + ":", state);
      SubBytes(state); // S-box substitution
      ShiftRows(state); // mix up rows
      AddRoundKey(state); // xor with expanded key
      Copy.copy(out, state);
   }

   // KeyExpansion: expand key, byte-oriented code, but tracks words
   private void KeyExpansion(byte[] key, byte[] w) {
      byte[] temp = new byte[4];
      // first just copy key to w
      int j = 0;
      while (j < 4*Nk) {
         w[j] = key[j++];
      }
      // here j == 4*Nk;
      int i;  
      while(j < 4*Nb*(Nr+1)) {
         i = j/4; // j is always multiple of 4 here
         // handle everything word-at-a time, 4 bytes at a time
         for (int iTemp = 0; iTemp < 4; iTemp++)
            temp[iTemp] = w[j-4+iTemp];
         if (i % Nk == 0) {
            byte ttemp, tRcon;
            byte oldtemp0 = temp[0];
            for (int iTemp = 0; iTemp < 4; iTemp++) {
               if (iTemp == 3) ttemp = oldtemp0;
               else ttemp = temp[iTemp+1];
               if (iTemp == 0) tRcon = tab.Rcon(i/Nk);
               else tRcon = 0;
               temp[iTemp] = (byte)(tab.SBox(ttemp) ^ tRcon);
            }
         }
         else if (Nk > 6 && (i%Nk) == 4) {
            for (int iTemp = 0; iTemp < 4; iTemp++)
               temp[iTemp] = tab.SBox(temp[iTemp]);
         }
         for (int iTemp = 0; iTemp < 4; iTemp++)
            w[j+iTemp] = (byte)(w[j - 4*Nk + iTemp] ^ temp[iTemp]);
         j = j + 4;
      }
   }

   // SubBytes: apply Sbox substitution to each byte of state
   private void SubBytes(byte[][] state) {
      for (int row = 0; row < 4; row++)
         for (int col = 0; col < Nb; col++)
            state[row][col] = tab.SBox(state[row][col]);
   }

   // ShiftRows: simple circular shift of rows 1, 2, 3 by 1, 2, 3
   private void ShiftRows(byte[][] state) {
      byte[] t = new byte[4];
       for (int r = 1; r < 4; r++) {
         for (int c = 0; c < Nb; c++)
            t[c] = state[r][(c + r)%Nb];
         for (int c = 0; c < Nb; c++)
            state[r][c] = t[c];
      }
   }

   public static byte[] hexStringToByteArray(String s) {
       int len = s.length();
       byte[] data = new byte[len / 2];
       for (int i = 0; i < len; i += 2) {
           data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                + Character.digit(s.charAt(i+1), 16));
       }
       return data;
   }

   private int getBit(byte val, int position)
   {
      int ans= (val >> position) & 1;
      return ans;
   }


   private static String splittohex(String s1)
   {
      // System.out.println("s1 initial " + s1);
      String s11=s1.substring(0,4);
      String s12=s1.substring(4,8);
      int i1=Integer.parseInt(s11,2);
      int i2=Integer.parseInt(s12,2);
      s11=Integer.toHexString(i1);
      s12=Integer.toHexString(i2);
      s1=s11+s12;
      // System.out.println("s1 final " + s1);
      return s1;
   }
   // MixColumns: complex and sophisticated mixing of columns
   private void MixColumns(byte[][] s) 
   {
      Print.printArray("current state ", s);
      int[][] temp=new int[4][8];
      for(int i=0;i<4;i++)
      {
         for(int j=0;j<4;j++)
         {
            for(int k=0;k<8;k++)
            {
               temp[j][7-k]=getBit(s[j][i],k);
            }
         }
         // printarray(temp);
         int[][] temp1=new int[4][2];
         int[][] temp2=new int[4][2];
         int[][] temp3=new int[4][2];
         int[][] temp4=new int[4][2];
         for(int j=0;j<2;j++)
         {
            for(int k=0;k<4;k++)
            {
               temp1[k][j]=temp[k][j];
               temp2[k][j]=temp[k][j+2];
               temp3[k][j]=temp[k][j+4];
               temp4[k][j]=temp[k][j+6];
            }
         }
         // System.out.println("temp1");
         // printarray(temp1);

         int[][] temp1new=new int[2][4];
         int[][] temp2new=new int[2][4];
         int[][] temp3new=new int[2][4];
         int[][] temp4new=new int[2][4];
         matrixtranspose(temp1,temp1new);
         matrixtranspose(temp2,temp2new);
         matrixtranspose(temp3,temp3new);
         matrixtranspose(temp4,temp4new);

         // System.out.println("temp1new");
         // printarray(temp1new);
         String s1="";
         StringBuilder sb=new StringBuilder(s1);
         for(int j=0;j<2;j++)
         {
            for(int k=0;k<4;k++)
            {
               sb.append(Integer.toString(temp1new[j][k]));
            }
         }
         s1=sb.toString();
         s1=splittohex(s1);
         
         // System.out.println("i1 " + i1);

         String s2="";
         sb=new StringBuilder(s2);
         for(int j=0;j<2;j++)
         {
            for(int k=0;k<4;k++)
            {
               sb.append(Integer.toString(temp2new[j][k]));
            }
         }
         s2=sb.toString();
         s2=splittohex(s2);
         // System.out.println("i2 " + i2);         

         String s3="";
         sb=new StringBuilder(s3);
         for(int j=0;j<2;j++)
         {
            for(int k=0;k<4;k++)
            {
               sb.append(Integer.toString(temp3new[j][k]));
            }
         }
         s3=sb.toString();
         s3=splittohex(s3);
         // System.out.println("i3 " + i3);

         String s4="";
         sb=new StringBuilder(s4);
         for(int j=0;j<2;j++)
         {
            for(int k=0;k<4;k++)
            {
               sb.append(Integer.toString(temp4new[j][k]));
            }
         }
         s4=sb.toString();
         s4=splittohex(s4);
         // System.out.println("i4 " + i4);

         byte b1=hexStringToByteArray(s1)[0];
         byte b2=hexStringToByteArray(s2)[0];  
         byte b3=hexStringToByteArray(s3)[0];
         byte b4=hexStringToByteArray(s4)[0];
         // System.out.println("s1 " + s1);
         // System.out.println("i1 " + i1);
         s[0][i]=b1;
         s[1][i]=b2;
         s[2][i]=b3;
         s[3][i]=b4;
         // Print.printArray("afdba ", s);
      }
   }

   private static void printarray(int[][] arr)
   {
      for(int i=0;i<arr.length;i++)
      {
         for(int j=0;j<arr[i].length;j++)
         {
            System.out.print(arr[i][j] + " ");
         }
         System.out.println();
      }
   }

   private static void matrixtranspose(int A[][], int[][] temp_new) 
   { 
      int i, j; 
      int[][] B=new int[2][4];
      for (i = 0; i < 2; i++)
      {
         for (j = 0; j < 4; j++) 
         {
            B[i][j] = A[j][i];
         }
      }
      for(int k=0;k<2;k++)
      {
         for(int l=0;l<4;l++)
         {
            temp_new[k][l]=B[k][l];
         }
      }  
   } 

   // AddRoundKey: xor a portion of expanded key with state
   private void AddRoundKey(byte[][] state) {
      for (int c = 0; c < Nb; c++)
         for (int r = 0; r < 4; r++)
            state[r][c] = (byte)(state[r][c] ^ w[wCount++]);
   }
}
// The class Tables gives access to computed tables and utility functions:


// AEStables: construct various 256-byte tables needed for AES
class AEStables {
   public AEStables() {
      loadE(); loadL(); loadInv();
      loadS(); loadInvS(); loadPowX();
   }

   private byte[] E = new byte[256]; // "exp" table (base 0x03)
   private byte[] L = new byte[256]; // "Log" table (base 0x03)
   private byte[] S = new byte[256]; // SubBytes table
   private byte[] invS = new byte[256]; // inverse of SubBytes table
   private byte[] inv = new byte[256]; // multiplicative inverse table
   private byte[] powX = new byte[15]; // powers of x = 0x02

   // Routines to access table entries
   public byte SBox(byte b) {
      return S[b & 0xff];
   }

   public byte invSBox(byte b) {
      return invS[b & 0xff];
   }

   public byte Rcon(int i) {
      return powX[i-1];
   }

   // FFMulFast: fast multiply using table lookup
   public byte FFMulFast(byte a, byte b){
      int t = 0;;
      if (a == 0 || b == 0) return 0;
      t = (L[(a & 0xff)] & 0xff) + (L[(b & 0xff)] & 0xff);
      if (t > 255) t = t - 255;
      return E[(t & 0xff)];
   }
      
   // FFMul: slow multiply, using shifting
   public byte FFMul(byte a, byte b) {
      byte aa = a, bb = b, r = 0, t;
      while (aa != 0) {
         if ((aa & 1) != 0)
            r = (byte)(r ^ bb);
         t = (byte)(bb & 0x80);
         bb = (byte)(bb << 1);
         if (t != 0)
            bb = (byte)(bb ^ 0x1b);
         aa = (byte)((aa & 0xff) >> 1);
      }
      return r;
   }

   // loadE: create and load the E table
   private void loadE() {
      byte x = (byte)0x01;
      int index = 0;
      E[index++] = (byte)0x01;
      for (int i = 0; i < 255; i++) {
         byte y = FFMul(x, (byte)0x03);
         E[index++] = y;
         x = y;
      }
   }

   // loadL: load the L table using the E table
   private void loadL() { // careful: had 254 below several places
      int index;
      for (int i = 0; i < 255; i++) {
          L[E[i] & 0xff] = (byte)i;
      }
   }

   // loadS: load in the table S
   private void loadS() { 
      int index;
      for (int i = 0; i < 256; i++)
          S[i] = (byte)(subBytes((byte)(i & 0xff)) & 0xff);
   }

   // loadInv: load in the table inv
   private void loadInv() { 
      int index;
      for (int i = 0; i < 256; i++)
          inv[i] = (byte)(FFInv((byte)(i & 0xff)) & 0xff);
   }

   // loadInvS: load the invS table using the S table
   private void loadInvS() {
      int index;
      for (int i = 0; i < 256; i++) {
          invS[S[i] & 0xff] = (byte)i;
      }
   }

   // loadPowX: load the powX table using multiplication
   private void loadPowX() {
      int index;
      byte x = (byte)0x02;
      byte xp = x;
      powX[0] = 1; powX[1] = x;
      for (int i = 2; i < 15; i++) {
          xp = FFMul(xp, x);
          powX[i] = xp;
      }
   }

   // FFInv: the multiplicative inverse of a byte value
   public byte FFInv(byte b) {
      byte e = L[b & 0xff];
      return E[0xff - (e & 0xff)];
   }

   // ithBIt: return the ith bit of a byte
   public int ithBit(byte b, int i) {
      int m[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};
      return  (b & m[i]) >> i;
   }

   // subBytes: the subBytes function
   public int subBytes(byte b) {
      byte inB = b;
      int res = 0;
      if (b != 0) // if b == 0, leave it alone
         b = (byte)(FFInv(b) & 0xff);
      byte c = (byte)0x63;
      for (int i = 0; i < 8; i++) {
         int temp = 0;
         temp = ithBit(b, i) ^ ithBit(b, (i+4)%8) ^ ithBit(b, (i+5)%8) ^
           ithBit(b, (i+6)%8) ^ ithBit(b, (i+7)%8) ^ ithBit(c, i);
         res = res | (temp << i);
      }
      return res;
   }
}
// The class GetBytes just reads bytes represented as Ascii hex characters (not in binary):


// GetBytes: fetch array of bytes, represented in hex
class GetBytes {
   private String fileName; // input filename
   private int arraySize; // number of bytes to read
   private Reader in;

   // GetBytes: constructor, opens input file
   public GetBytes(String file, int n) {
      fileName = file;
      arraySize = n;
      try {
         in = new FileReader(fileName);
      } catch (IOException e) {
         System.out.println("Exception opening " + fileName);
      }
   }

   // getNextChar: fetches next char
   private char getNextChar() {
      char ch = ' '; // = ' ' to keep compiler happy
      try {
         ch = (char)in.read();
      } catch (IOException e) {
         System.out.println("Exception reading character");
      }
      return ch;
   }

   // val: return int value of hex digit
   private int val(char ch) {
      if (ch >= '0' && ch <= '9') return ch - '0';
      if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
      if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
      return -1000000;
   }

   // getBytes: fetch array of bytes in hex
   public byte[] getBytes() {
      byte[] ret = new byte[arraySize];
      for (int i = 0; i < arraySize; i++) {
         char ch1 = getNextChar();
         char ch2 = getNextChar();
         ret[i] = (byte)(val(ch1)*16 + val(ch2));
      }
      return ret;
   }
}
// The class Copy copies arrays back and forth for the AES:


// Copy: copy arrays of bytes
class Copy {
   private static final int Nb = 4;
   // copy: copy in to state
   public static void copy(byte[][] state, byte[] in) {
      int inLoc = 0;
      for (int c = 0; c < Nb; c++)
         for (int r = 0; r < 4; r++)
            state[r][c] = in[inLoc++];
   }
            
   // copy: copy state to out
   public static void copy(byte[] out, byte[][] state) {
      int outLoc = 0;
      for (int c = 0; c < Nb; c++)
         for (int r = 0; r < 4; r++)
            out[outLoc++] = state[r][c];
   }      
}
// The class Print prints 1-and 2-dimensional arrays of bytes for debugging:


// Print: print arrays of bytes
class Print {
   private static final int Nb = 4;
   private static String[] dig = {"0","1","2","3","4","5","6","7",
                           "8","9","a","b","c","d","e","f"};

   // hex: print a byte as two hex digits
   public static String hex(byte a) {
      return dig[(a & 0xff) >> 4] + dig[a & 0x0f];
   }

   public static void printArray(String name, byte[] a) {
      System.out.print(name + " ");
      for (int i = 0; i < a.length; i++)
         System.out.print(hex(a[i]) + " ");
      System.out.println();
   }

   public static void printArray(String name, byte[][] s) {
      System.out.print(name + " ");
      for (int c = 0; c < Nb; c++)
         for (int r = 0; r < 4; r++)
            System.out.print(hex(s[r][c]) + " ");
      System.out.println();
   }
}
// The class AEStest is a driver for testing encryption:


// AEStest: test AES encryption
public class AEStest {

   public static void main(String[] args) {
      // for 128-bit key, use 16, 16, and 4 below
      // for 192-bit key, use 16, 24 and 6 below
      // for 256-bit key, use 16, 32 and 8 below
      GetBytes getInput = new GetBytes("plaintext1.txt", 16);
      byte[] in = getInput.getBytes();
      GetBytes getKey = new GetBytes("key1.txt", 16);
      byte[] key = getKey.getBytes();
      AESencrypt aes = new AESencrypt(key, 4);
      Print.printArray("Plaintext:     ", in);
      Print.printArray("Key:           ", key);
      byte[] out = new byte[16];
      aes.Cipher(in, out);
      Print.printArray("Ciphertext:    ", out);
   }
}