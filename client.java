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
import java.net.*;  
import java.net.*;  
import java.io.*;
import java.math.*;
import java.util.*;
import java.security.*;
import java.math.BigInteger; 
import java.security.MessageDigest; 
import java.security.NoSuchAlgorithmException; 

class RSA
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

class Client{
    
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
RSA rsa=new RSA();
Socket s=new Socket("localhost",3333);  
DataInputStream din=new DataInputStream(s.getInputStream());  
DataOutputStream dout=new DataOutputStream(s.getOutputStream());  
BufferedReader br=new BufferedReader(new InputStreamReader(System.in));  

System.out.println("----------DRIVING LICENSE CHECKER-----------");
System.out.println("Please enter the following details mentioned");
System.out.println("ID Of User:");
String id;
id=br.readLine();
System.out.println("Name Of User:");
String name;
name=br.readLine();
System.out.println("DOB Of User:");
String dob;        
dob=br.readLine();

System.out.println("Encrypting data using public key cryptography:");

        
String message=id+" "+name+" "+dob;
String md5=getMd5(message);
String mm="";
String e="8341377783935280518314864324846467968196580923104766515376036989463817968144722249732570615816127403402119115571350077228106047154681405539846232720871197";
BigInteger PublicKey=new BigInteger(e);
String n="17712261737182957839711027485626381767130000475050712201085068164322551658308830627788962973697761257512735585140165232283185792244437943379917751917553993372886792944912230482297510394633258901156149895759976244491110294845921390391825263257070024886680797904317596879743430528527642763223397616149212600420570984542503357196848516772880890380045664992650065269589354095298715123854931254737631691526850849419094093847613792004634938211120993342553738412047824477800371238551634428787373538592866690117214101918805722563917421298768897482180931554254973396029607482099029615494148017077749769715577824866920078529719";
BigInteger largenumber=new BigInteger(n);
int nonce=(int) (Math.random()*Integer.MAX_VALUE);
String messagets=nonce+" "+id+" "+md5;
byte[] data=messagets.getBytes();
byte[] encdata;
        encdata = rsa.encrypt(data, PublicKey, largenumber);
dout.writeInt(encdata.length);
dout.write(encdata);
dout.flush();
int sstr2=din.readInt();
byte[] c=new byte[sstr2];
din.read(c);
c=rsa.decrypt(c, PublicKey, largenumber);
String valtoconfirm="";
for(int i=0;i<c.length;i++){
    valtoconfirm=valtoconfirm+((char)c[i]);
}

String[] details=valtoconfirm.split("//");

if(Integer.parseInt(details[0])==nonce)
System.out.println("Server says: "+details[1]);
else
System.out.println("Replay Attack attempted try once again");
    
String str="",str2="";  
  
dout.close();  
s.close();  
}}    
