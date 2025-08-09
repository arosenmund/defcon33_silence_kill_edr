# Custom Windows API Based Evasions

This section has a number of different ideas for evading different kind of monitoring and edr tooling.  They are all experimental but meant for educational training and inspiration.

1. On the **Windows Target 2** machine. I is somewhat disabled but will allow us to go through these though experiments.
2. Swap back and forth between the files in the C++ folders in the Operator Desktop, and running them on **Windows Target 2**
> Follow along, I will walk through each of the following, and discuss what they are doing on the system, and issues that they run into and why, and how you could solve them.
> Detecting common EDR hooking methods.
```
./c++/detect-hooks-dlls.exe
```
> Unhooking APIs.
```
unhooker.exe
```
> Detecting all process dlls, including PEB walk.
```
detect-att.exe --all
```
>Unload edr dlls.
```
dll-unloader.exe
```

2. Next check out some fun thoughts on potential tricks for disabling monitoring indirectly with golang.
in the ./golang/* folder.
> Disable service.
```
disable-service.exe
```
> Delete or modify logging file.
```
file-stomp-OG.exe
```
> Stop external monitoring with firewall rule.
```
firewall-rule.exe
```
> Route to nothing!
```
re-route.exe
```

**Discuss Snuff-Traffic** 


Time to wrap it up!!! Thanks you!



