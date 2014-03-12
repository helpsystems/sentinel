##What is Sentinel?

Sentinel is a command line tool able to protect Windows 32 bit programs against exploits targeted by attackers or viruses. It can protect your programs against 0-day attacks or publicly known bugs.

##Why Sentinel?

When a 0-day attack is used in the wild, nobody knows about the existence of this bug except the attacker himself. Some antiviruses implement heuristics to detect new attacks but usually they are unreliable. Sometimes, your computer is not up to date, in this case you are vulnerable to attacks against public bugs.

In both cases, one way to protect your "vulnerable programs" against old or new attacks is adding extra protections (usually, exploit mitigations).

##What kind of programs can Sentinel protect?

Any 32 bit program can be protected by Sentinel.
E.g: "Internet Explorer", "Acrobat Reader", "Word", "Excel", your applications, etc ..

##Which Windows versions Does Sentinel support?

From Windows XP SP0 to the last Windows version.

##What kind of exploit attacks can Sentinel stop?

Sentinel is able to detect attacks against user mode binary bugs.

Binary bugs can be understood as bugs where the instruction pointer (EIP) can be modified.
E.g: Stack overflows, Heap overflows, memory corruptions, Use after-free, etc.

What kind of exploit attack behavior can Sentinel detect?

 * ROP activity
 * Stack Pivoting
 * Invalid Caller
 * Return Address modification
 * Stack Execution
 * Stack Returning (previous step to stack execution)
 * Base Pointer modification (experimental)

##Is it necessary to install Sentinel to use?

No instalation needed.

##Can a program be protected while running?

Yes, Sentinel is able to protect programs while running.

##What is the execution overhead in protected programs?

Depends on the protection level:

 * Default ( only targeted functions ): 0% ~ 1% ?
 * Default + module protection ( one or more modules ): Depends on the use of the protected module by the program

##Licensing

Sentinel is released under version 3 of the GNU General Public License.

