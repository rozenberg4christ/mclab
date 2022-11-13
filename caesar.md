#Caesar Cipher
- The code is self explanatory

#Code
`
import java.util.*;
public class Caeasar {
    public static StringBuffer encrypt(String text,int s){
        StringBuffer res=new StringBuffer();
        for(int i=0;i<text.length();i++){
            if(Character.isUpperCase(text.charAt(i))){
                char ch=(char)(((int)text.charAt(i)+s-65)%26+65);
                res.append(ch);
            }
            else{
                char ch=(char)(((int)text.charAt(i)+s-97)%26+97);
                res.append(ch);
            }
        }
        return res;
    }
    public static void main(String[] args){
        Scanner sc = new Scanner(System.in);
        String text=sc.nextLine();
        int s=sc.nextInt();
        System.out.print("Text : "+text);
        System.out.print("\nShift : "+s);
        System.out.print("\nCipher : "+encrypt(text,s));
    }
}
`
