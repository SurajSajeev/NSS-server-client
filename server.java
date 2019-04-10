/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */



/**
 *
 * @author suraj
 */
import java.io.*;  
import java.io.*; 
import java.io.*;
import java.math.*;
import java.math.BigInteger; 
import java.net.*;
import java.net.*;
import java.security.*;
import java.security.MessageDigest; 
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.*;
class RSAs
{
     
 
    @SuppressWarnings("deprecation")
    
     String bytesToString(byte[] encrypted)
    {
        String test = "";
        for (byte b : encrypted)
        {
            test += Byte.toString(b);
        }
        return test;
    }
 
    // Encrypt message
    public byte[] encrypt(byte[] message,BigInteger e,BigInteger N)
    {
        return (new BigInteger(message)).modPow(e, N).toByteArray();
    }
 
    // Decrypt message
    public byte[] decrypt(byte[] message,BigInteger d,BigInteger N)
    {
        return (new BigInteger(message)).modPow(d, N).toByteArray();
    }
}

class Server{
    private static int i;
public static String getMd5(String input) throws NoSuchAlgorithmException 
    { 
        try { 
  
            // Static getInstance method is called with hashing MD5 
            MessageDigest md = MessageDigest.getInstance("MD5"); 
  
            // digest() method is called to calculate message digest 
            //  of an input digest() return array of byte 
            byte[] messageDigest = md.digest(input.getBytes()); 
  
            // Convert byte array into signum representation 
            BigInteger no = new BigInteger(1, messageDigest); 
  
            // Convert message digest into hex value 
            String hashtext = no.toString(16); 
            while (hashtext.length() < 32) { 
                hashtext = "0" + hashtext; 
            } 
            return hashtext; 
        }  
  
        // For specifying wrong message digest algorithms 
        catch (NoSuchAlgorithmException e) { 
            System.out.println( e); 
            throw e;
        } 
    }
    
 
public static void main(String args[])throws Exception{
    while(true){
 Map< Integer,String> hash =new HashMap< Integer,String>();
 Map< Integer,Date> doi =new HashMap< Integer,Date>();
 Map< Integer,Boolean> valida =new HashMap< Integer,Boolean>();
hash.put(new Integer(1), new String("fc12064919184c25dd787c4c794c24d4"));
hash.put(new Integer(2), new String("Saurabh"));
hash.put(new Integer(3), new String("Sriraam"));
doi.put(new Integer(1), new Date(2021,10,17));
doi.put(new Integer(2), new Date(2019,02,11));
doi.put(new Integer(3), new Date(2010,04,02));
valida.put(new Integer(1), new Boolean(true));
valida.put(new Integer(2), new Boolean(false));
valida.put(new Integer(3), new Boolean(false));
ServerSocket ss=new ServerSocket(3333);  
Socket s=ss.accept();  
DataInputStream din=new DataInputStream(s.getInputStream());  
DataOutputStream dout=new DataOutputStream(s.getOutputStream());  
BufferedReader br=new BufferedReader(new InputStreamReader(System.in));  
int len=din.readInt();
byte[] data = new byte[len];
din.readFully(data, 0, len);
System.out.println(data);
RSAs rsa=new RSAs();
BigInteger d=new BigInteger("1465340123272007697985138417999265102755888992325927536532365361677263891929117169011976191046550828900286821147374352915139175755753942244632014547343852756715554475337137297489795984299304843070185438183969499259635421988202711366314695123631158667316607172700153224579419915222800233758300369793013079305928593697323693524367099061780805855925366217023963922188619959831830636773690136716731120696668586352367007568090921079480543334176560837706711120648058143595846656915756448635631641384257600922278703139115434519872614408835680380366890196758367610908573024293301384508661231829822747751823415403247166507797");
BigInteger n=new BigInteger("17712261737182957839711027485626381767130000475050712201085068164322551658308830627788962973697761257512735585140165232283185792244437943379917751917553993372886792944912230482297510394633258901156149895759976244491110294845921390391825263257070024886680797904317596879743430528527642763223397616149212600420570984542503357196848516772880890380045664992650065269589354095298715123854931254737631691526850849419094093847613792004634938211120993342553738412047824477800371238551634428787373538592866690117214101918805722563917421298768897482180931554254973396029607482099029615494148017077749769715577824866920078529719");
byte[] decoded=rsa.decrypt(data, d, n);
String valtoconfirm="";
for(int i=0;i<decoded.length;i++){
    valtoconfirm=valtoconfirm+((char)decoded[i]);
}
System.out.println(valtoconfirm);
String[] na= valtoconfirm.split(" ",3);
        
long nonce=Long.parseLong(na[0]);
System.out.print("nonce="+nonce);
int id=Integer.parseInt(na[1]);

String md5=na[2];
SimpleDateFormat ft = new SimpleDateFormat ("dd-MM-yyyy");


if (hash.containsKey(id)) {
    Object value = hash.get(id);
    
   if(md5.equals(value.toString()))
   {
    System.out.println("verified");
    String msg;
    Date dt=new Date();
    ;
    System.out.println(valida.get(id)+" "+ft.format((Date)doi.get(id))+" "+ft.format(new Date()));
    if(((boolean)valida.get(id))&&(((Date)doi.get(id)).compareTo(dt))>0)
   msg="Verified the credentials the user is authentic";
    else if(!(boolean)valida.get(id))
   msg="Not a valid user anymore";
    else
   msg="Already expired,renewal must be done";  
   msg=nonce+"//"+msg;
   System.out.print(msg);
   byte[] sam;
   sam=msg.getBytes();
   sam=rsa.encrypt(sam,d,n);
   
    dout.writeInt(sam.length);
    dout.write(sam);  
   dout.flush();  

   }
   else{
   dout.writeUTF("Not Verified,check credentials are valid");  
   dout.flush();  
   }

}
else{
}

    
 
  
din.close();  
s.close();  
ss.close();  
}}}     
