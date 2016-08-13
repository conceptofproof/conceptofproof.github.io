---
layout: post
published: true
title: Prime time to hit the switch
---
Do you have a talent for factorizing arbitrary large random numbers? I'll show you how to build an educational prime number guessing game using an Arduino that takes roughly 2 hours to build. It will challenge you with random numbers to put your arithmetic skills to the test.

The aim of the game is simple: correctly identify whether a number is prime or not. 

_A prime number is a whole number greater than 1, whose only two whole-number factors are 1 and itself._

[![Arduino prime number game](http://img.youtube.com/vi/bANKbJNpxhU/0.jpg)](http://www.youtube.com/watch?v=bANKbJNpxhU "Video Title")

To begin a number is displayed on the screen and you are presented with the option to select 'yes' or 'no'. The question is simply: 'Is this number a Prime number or not?'.

The screen also displays your score so you can challenge yourself or your friends and family.

My implementation uses an Arduino UNO Revision 3, If you're interested in playing or building one for yourself I'll show you how below.

### Instructions

To build this circuit, with or without a breadboard, the components you'll need are:

1. Arduino UNO (used revision 3)
2. Potentiometer
3. Two Switches for input controls, any type you feel like is ok I used push-to-make buttons
4. Any analog input (Capacitor, potentiometer, temp sensors or photo-resistors are all great)
5. An LCD display (at least 16 x 2) I used [LCM1602C]
6. You can power it from 9v battery or USB cable.
7. 10k ohm step down resitors

The circuit looks as follows:

![component view](https://raw.githubusercontent.com/CodeMuz/arduino-projects/master/Extra/Prime_Number_Game/component_vie.png)

I've prototyped the board using circuits.io [here](https://circuits.io/circuits/2458049-prime-number-guesser) for you to play around with. You'll notice the jump wires have different colours to the my circuit as it's clearer to follow the colours btu unfortunately I don't yet have wires with these colours. 

The source code is available to [download](https://github.com/CodeMuz/arduino-projects/blob/master/Extra/Prime_Number_Game/primegame.ino) from github under CC BY SA 3.0.

## Schematics

![circuit diagram](https://raw.githubusercontent.com/CodeMuz/arduino-projects/master/Extra/Prime_Number_Game/circuit-diagram.png)

![copper-diagram](https://raw.githubusercontent.com/CodeMuz/arduino-projects/master/Extra/Prime_Number_Game/copper-diagram.png)

## Implementation

An interesting things to note in the source code is the random number generator code:

~~~
/*
Returns an odd integer between 0 and maxNumber
*/
unsigned long generateNewNumber() {

  unsigned long n = random(11 * analogRead(seedPin)) % maxNumber;
  
  //bias distribution to return higher percent composite
  if(n % 2 == 0 || n % 3 == 0 || n == 1 || n == prevNumber){
    return generateNewNumber();  
  }
  
  prevNumber = n;

  return n;
}
~~~

Firstly I'm using the usigned long data type as that holds 4 bytes of positive numbers (0 to 4,294,967,295), this is because prime numbers are by definition positive numbers. For speed with primality test and to reduce difficulty I've set the max to the 5th Mersenne Prime 8191.

The analogue input device is required to provide more random information to the arduino _random_ function when generating the prime numbers. There's also a check so that the same number does not appear twice as this would be sub optimal for a quiz type game.

The Primality test function is just a naive implementation which is practical for small numbers and tests all the potential prime factors up to the square root of n.

~~~
boolean isPrime(long n) {
  if (n <= 1) {
    return false;
  } else if (n <= 3 ) {
    return true;
  } else if (n % 2 == 0 || n % 3 == 0) {
    return false;
  }
  int i = 5;
  while ((i * i) <= n) {
    if (n % i == 0 || n % (i + 2) == 0) {
      return false;
    }
    i = i + 6;
  }
  return true;
}
~~~

### Testing:

Running the circuit on 10,000 numbers for 6,421ms generates 3796 primes indicating that if you were to select 'No' every answer you would have a 62.04% rate of success.

A better approach would be using the deterministic [Baillie–PSW](https://en.wikipedia.org/wiki/Baillie%E2%80%93PSW_primality_test).

Potential extensions to this project, excluding optimizations, include: 

- Varying the input type for responding to the quiz (movement sensors or variable resistors, or connecting to the device over bluetooth or wifi)
- Modifying the response interface, i.e with LEDs or Piezos
- An alternative number game, for example instead of isPrime() you could ask isPerfectNumber() or use any equation with multiples, powers and divisors.
