# Programming Assignment 2
By Kang Shao Quan (1004238) and Poh Jin Heng Princeton (1004594) :D
# So you asked how to run the code young grasshopper?
1. You first have to compile CP1.java and SP1.java separately on 2 different terminals
```
FirstTerminal: javac SP1.java
---
SecondTerminal: javac CP1.java
``` 
2. The once you see the class binaries compile, you can run the next 2 lines of code sequentially on their respective terminals.
```
FirstTerminal: java SP1
---
SecondTerminal: java CP1 {any of the input txt files}
e.g
example 1: java CP1 100.txt
example 2: java CP1 100.txt 200.txt
``` 
- You should see the time taken for the program to run printed out in the terminal
- You should also receive back the files from the server (e.g recv_100.txt)

3. Now it is time to try for CP2.java and SP2.java. Similarly, compile it first.
```
FirstTerminal: javac SP2.java
---
SecondTerminal: javac CP2.java
``` 
4. Next, run the next 2 lines of code sequentially on their respective terminals.
```
FirstTerminal: java SP2
---
SecondTerminal: java CP2 {any of the input txt files}
e.g
example 1: java CP1 500.txt
example 2: java CP1 500.txt 200.txt 100000.txt
``` 
- The expected outcome is the same as that from step 2.

# The end
Hope you enjoyed it! :)