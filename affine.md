# Affine Cipher

# Code
```java
import java.util.*;
public class Affine {
    public static int gcd(int a,int b){
        if(b==0){
            return a;
        }
        else{
            return gcd(b,Math.abs(a-b));
        }
    }
    public static String encrypt(char[] text,int a,int b){
        String cipher="";
        for(int i=0;i<text.length;i++){
            if(text[i]!=' '){
                cipher=cipher+(char)((((a*(text[i]-'A'))+b)%26)+'A');
            }
            else{
                cipher+=text[i];
            }
        }
        return cipher;
    }
    public static int inverse(int a){
        int res,i;
        for(i=0;i<26;i++){
            res=(a*i)%26;
            if(res==1)
                return i;
        }
        return i;
    }
     public static String decrypt(char[] text,int a,int b){
        int a_inv=inverse(a);
        String decipher="";
        for(int i=0;i<text.length;i++){
            if(text[i]!=' '){
                decipher=decipher+(char)(((a_inv*((text[i]+'A'-b))%26))+'A');
            }
            else{
                decipher+=text[i];
            }
        }
        return decipher;
    }
    public static void main(String[] args){
        Scanner sc = new Scanner(System.in);
        String text=sc.nextLine();
        int a=sc.nextInt();
        int b=sc.nextInt();
        if(gcd(a,b)==1){
            System.out.print("GCD is 1\n");
        }
        else{
            System.out.print("We cannot proceed with this values of a and b");
            System.exit(1);
        }
        System.out.print("Text : "+text);
        System.out.print("\na : "+a);
        System.out.print("\nb : "+b);
        System.out.print("\nCipher : "+encrypt(text.toCharArray(),a,b));
        String re=encrypt(text.toCharArray(),a,b);
        System.out.print("\nDecrypt : "+decrypt(re.toCharArray(),a,b));
    }
}
```