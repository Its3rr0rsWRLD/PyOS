import random
print("\nWassup hommie, care to play a game?\n")
print("\nI'll try to guess the number YOU choose.\n")
print("\nPlease tell me the borders: \n")

a = int(input("\nMin: "))
b = int(input("\nMax: "))
while True:
 if(a > b):
    (print("\nError, min can't be more than max :| \n"))
    a = int(input("\nMin: "))
    b = int(input("\nMax: "))
 else:
     break;
breaking = "------------"
print("\nNow type in the number: \n")
c = int(input(" "))
tries = 1;
d = random.randint(a, b)
while True:
   if(d == c and tries == 1):
            print("\nGuess 1: " + str(d))
            print("\nHA, gotcha. I got it in 1 time!\n")
            print("\nWanna go again? y for yes and any key for no. \n")
            i = input("");
            if(i == "y"):
               print(breaking * 10);
               a = int(input("\nMin: "))
               b = int(input("\nMax: "))

               print("\nNow type in the number")
               c = int(input("\n "))
               tries = 1;
               if(a > b):
                      print("\nError, min can't be more than max. ")
                      a = int(input("\nMin: "))
                      b = int(input("\nMax: "))
                      print("\nNow type in the number")
                      c = int(input(" "))
               else:
                d = random.randint(a, b)
               
            else:
              break;
   elif(d == c):
            print("HA, gotcha. I got it in " + str(tries - 1) + " times!")
            print("Wanna go again? y for yes and anykey for no. ")
            i = input("");
            if(i == "y"):
              print(breaking * 10);
              a = int(input("Min: "))
              b = int(input("Max: "))

              print("now type in the number")
              c = int(input(" "))
              tries = 1;
              if(a > b):
                      print("error, min can't be more than max. ")
                      a = int(input("Min: "))
                      b = int(input("Max: "))
                      print("\nnow type in the number")
                      c = int(input(" "))
              else:
                d = random.randint(a, b)
          
            else:
              break;
    
   elif(c > b):
      print("\nerror, number can't be bigger than max.");
      print("\nWanna go again? y for yes and anykey for no. ")
      i = input("");
      if(i == "y"):
          print(breaking * 10);
          a = int(input("Min: "))
          b = int(input("Max: "))

          print("\nnow type in the number")
          c = int(input(" "))
          tries = 1;
          if(a > b):
                (print("\nerror, min can't be more than max. "))
                a = int(input("Min: "))
                b = int(input("Max: "))
                print("\nnow type in the number")
                c = int(input(" "))
          else:
             d = random.randint(a, b)

      else:
          break;
   elif(c < a):
      print("\nError, number can't be smaller than min.");
      print("\nWanna go again? y for yes and anykey for no. ")
      i = input("");
      if(i == "y"):
          print(breaking * 10);
          a = int(input("Min: "))
          b = int(input("Max: "))

          print("\nNow type in the number")
          c = int(input(" "))
          tries = 1;
          if(a > b):
                      print("\nError, min can't be more than max. ")
                      a = int(input("Min: "))
                      b = int(input("Max: "))
                      print("\nNow type in the number")
                      c = int(input(" "))
          else:
            d = random.randint(a, b)
      else:
            break;
   elif(d < c):
          a = d + 1;
          d = random.randint(a, b)
          print( "guess " + str(tries) + " :" + str(d));
          tries += 1;

   elif(d > c):
      b = d - 1;
      d = random.randint(a, b)
      print( "guess " + str(tries) + " :" + str(d))  
      tries += 1

input=""
