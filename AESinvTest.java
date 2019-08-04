class AESdecrypt {
   public final int Nb = 4; // words in a block, always 4 for now
   public int Nk; // key length in words
   public int Nr; // number of rounds, = Nk + 6
   private int wCount; // position in w (= 4*Nb*(Nr+1) each encrypt)
   AEStables tab; // all the tables needed for AES
   byte[] w; // the expanded key

   // AESdecrypt: constructor for class.  Mainly expands key
   public AESdecrypt(byte[] key, int NkIn) {
      Nk = NkIn; // words in a key, = 4, or 6, or 8
      Nr = Nk + 6; // corresponding number of rounds
      tab = new AEStables(); // class to give values of various functions
      w = new byte[4*Nb*(Nr+1)]; // room for expanded key
      KeyExpansion(key, w); // length of w depends on Nr
   }

   // InvCipher: actual AES decryption
   public void InvCipher(byte[] in, byte[] out) {
      wCount = 4*Nb*(Nr+1); // count bytes during decryption
      byte[][] state = new byte[4][Nb]; // the state array
      Copy.copy(state, in); // actual component-wise copy
      InvAddRoundKey(state); // xor with expanded key
      for (int round = Nr-1; round >= 1; round--) {
         Print.printArray("Start round  " + (Nr - round) + ":", state);
         InvShiftRows(state); // mix up rows
         InvSubBytes(state); // inverse S-box substitution
         InvAddRoundKey(state); // xor with expanded key
         InvMixColumns(state); // complicated mix of columns
      }
      Print.printArray("Start round  " + Nr + ":", state);
      InvShiftRows(state); // mix up rows
      InvSubBytes(state); // inverse S-box substitution
      InvAddRoundKey(state); // xor with expanded key
      Copy.copy(out, state);
   }

   // KeyExpansion: expand key, byte-oriented code, but tracks words
   //  (the same as for encryption)
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

   // InvSubBytes: apply inverse Sbox substitution to each byte of state
   private void InvSubBytes(byte[][] state) {
      for (int row = 0; row < 4; row++)
         for (int col = 0; col < Nb; col++)
            state[row][col] = tab.invSBox(state[row][col]);
   }

   // InvShiftRows: right circular shift of rows 1, 2, 3 by 1, 2, 3
   private void InvShiftRows(byte[][] state) {
      byte[] t = new byte[4];
      for (int r = 1; r < 4; r++) {
         for (int c = 0; c < Nb; c++)
            t[(c + r)%Nb] = state[r][c];
         for (int c = 0; c < Nb; c++)
            state[r][c] = t[c];
      }
   }

   private static void printarray(int[] arr)
   {
      for(int i=0;i<arr.length;i++)
      {
         System.out.print(arr[i] + " ");
      }
      System.out.println();
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
   // InvMixColumns: complex and sophisticated mixing of columns
   private void InvMixColumns(byte[][] s) 
   {
      // Print.printArray("current state ", s);
      for(int i=0;i<4;i++)
      {
         int[] series1=new int[8];
         for(int j=0;j<8;j++)
         {
            series1[7-j]=getBit(s[0][i],j);
         }
         int[][] temp1new=new int[2][4];
         for(int j=0;j<2;j++)
         {
            for(int k=0;k<4;k++)
            {
               temp1new[j][k]=series1[4*j+k];
            }
         }
         // System.out.println("series1");
         // printarray(series1);

         // System.out.println("temp1new");
         // printarray(temp1new);
         int[] series2=new int[8];
         for(int j=0;j<8;j++)
         {
            series2[7-j]=getBit(s[1][i],j);
         }
         int[][] temp2new=new int[2][4];
         for(int j=0;j<2;j++)
         {
            for(int k=0;k<4;k++)
            {
               temp2new[j][k]=series2[4*j+k];
            }
         }

         int[] series3=new int[8];
         for(int j=0;j<8;j++)
         {
            series3[7-j]=getBit(s[2][i],j);
         }
         int[][] temp3new=new int[2][4];
         for(int j=0;j<2;j++)
         {
            for(int k=0;k<4;k++)
            {
               temp3new[j][k]=series3[4*j+k];
            }
         }

         int[] series4=new int[8];
         for(int j=0;j<8;j++)
         {
            series4[7-j]=getBit(s[3][i],j);
         }
         int[][] temp4new=new int[2][4];
         for(int j=0;j<2;j++)
         {
            for(int k=0;k<4;k++)
            {
               temp4new[j][k]=series4[4*j+k];
            }
         }

         int[][] temp1=new int[4][2];
         int[][] temp2=new int[4][2];
         int[][] temp3=new int[4][2];
         int[][] temp4=new int[4][2];
         matrixtranspose(temp1new,temp1);
         matrixtranspose(temp2new,temp2);
         matrixtranspose(temp3new,temp3);
         matrixtranspose(temp4new,temp4);

         // System.out.println("temp1");
         // printarray(temp1);
         
         int[] series1new=new int[8];
         series1new[0]=temp1[0][0];
         series1new[1]=temp1[0][1];
         series1new[2]=temp2[0][0];
         series1new[3]=temp2[0][1];
         series1new[4]=temp3[0][0];
         series1new[5]=temp3[0][1];
         series1new[6]=temp4[0][0];
         series1new[7]=temp4[0][1];

         int[] series2new=new int[8];
         series2new[0]=temp1[1][0];
         series2new[1]=temp1[1][1];
         series2new[2]=temp2[1][0];
         series2new[3]=temp2[1][1];
         series2new[4]=temp3[1][0];
         series2new[5]=temp3[1][1];
         series2new[6]=temp4[1][0];
         series2new[7]=temp4[1][1];

         int[] series3new=new int[8];
         series3new[0]=temp1[2][0];
         series3new[1]=temp1[2][1];
         series3new[2]=temp2[2][0];
         series3new[3]=temp2[2][1];
         series3new[4]=temp3[2][0];
         series3new[5]=temp3[2][1];
         series3new[6]=temp4[2][0];
         series3new[7]=temp4[2][1];

         int[] series4new=new int[8];
         series4new[0]=temp1[3][0];
         series4new[1]=temp1[3][1];
         series4new[2]=temp2[3][0];
         series4new[3]=temp2[3][1];
         series4new[4]=temp3[3][0];
         series4new[5]=temp3[3][1];
         series4new[6]=temp4[3][0];
         series4new[7]=temp4[3][1];

         String s1="";
         StringBuilder sb=new StringBuilder(s1);
         for(int j=0;j<8;j++)
         {
            sb.append(Integer.toString(series1new[j]));
         }
         s1=sb.toString();
         s1=splittohex(s1);

         String s2="";
         sb=new StringBuilder(s2);
         for(int j=0;j<8;j++)
         {
            sb.append(Integer.toString(series2new[j]));
         }
         s2=sb.toString();
         s2=splittohex(s2);

         String s3="";
         sb=new StringBuilder(s3);
         for(int j=0;j<8;j++)
         {
            sb.append(Integer.toString(series3new[j]));
         }
         s3=sb.toString();
         s3=splittohex(s3);

         String s4="";
         sb=new StringBuilder(s4);
         for(int j=0;j<8;j++)
         {
            sb.append(Integer.toString(series4new[j]));
         }
         s4=sb.toString();
         s4=splittohex(s4);

         byte b1=hexStringToByteArray(s1)[0];
         byte b2=hexStringToByteArray(s2)[0];  
         byte b3=hexStringToByteArray(s3)[0];
         byte b4=hexStringToByteArray(s4)[0];
         
         s[0][i]=b1;
         s[1][i]=b2;
         s[2][i]=b3;
         s[3][i]=b4;
         
      }

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

   public static byte[] hexStringToByteArray(String s) {
       int len = s.length();
       byte[] data = new byte[len / 2];
       for (int i = 0; i < len; i += 2) {
           data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                + Character.digit(s.charAt(i+1), 16));
       }
       return data;
   }

   private static void matrixtranspose(int A[][], int[][] temp_new) 
   { 
      int i, j; 
      int[][] B=new int[4][2];
      for (i = 0; i < 4; i++)
      {
         for (j = 0; j < 2; j++) 
         {
            B[i][j] = A[j][i];
         }
      }
      for(int k=0;k<4;k++)
      {
         for(int l=0;l<2;l++)
         {
            temp_new[k][l]=B[k][l];
         }
      }  
   } 

   private int getBit(byte val, int position)
   {
      int ans= (val >> position) & 1;
      return ans;
   }

   // InvAddRoundKey: same as AddRoundKey, but backwards
   private void InvAddRoundKey(byte[][] state) {
   for (int c = Nb - 1; c >= 0; c--)
      for (int r = 3; r >= 0 ; r--)
         state[r][c] = (byte)(state[r][c] ^ w[--wCount]);
   }
}

// AESinvTest: test AES decryption
public class AESinvTest {

   public static void main(String[] args) {
      // for 128-bit key, use 16, 16, and 4 below
      // for 192-bit key, use 16, 24 and 6 below
      // for 256-bit key, use 16, 32 and 8 below
      GetBytes getInput = new GetBytes("ciphertext1.txt", 16);
      byte[] in = getInput.getBytes();
      // byte[] in={(byte)0xf7, (byte)0x36, (byte)0x85, (byte)0x2e, (byte)0x28, (byte)0x77, (byte)0xc9, (byte)0xe3,
      //             (byte)0x79, (byte)0x32, (byte)0x13, (byte)0x8f, (byte)0xbf, (byte)0x5d, (byte)0xd1, (byte)0x22};

      GetBytes getKey = new GetBytes("key1.txt", 16);
      byte[] key = getKey.getBytes();
      AESdecrypt aesDec = new AESdecrypt(key, 4);
      Print.printArray("Ciphertext:    ", in);
      Print.printArray("Key:           ", key);
      byte[] out = new byte[16];
      aesDec.InvCipher(in, out);
      Print.printArray("Plaintext:     ", out);
   }
}