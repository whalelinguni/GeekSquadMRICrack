

# Combined GS(I) MRI DLL Mods/Patches/Crack(s)/serial.txt.bat Informations

**WORK IN PROGESS**
**Will update with a loader.** 
###### Or I won't. Depends on how quickly I get bored.

### Update 09-30 - Notes-09-30.txt in repo with more detailed informations.
Ehhhh.... while the method I used attempting to block the calling home does technically *work*... Additionally I believe there's something that is being sent for some type of auth, which I seems now it is blocked/banned from GS Servers.

System Updater does not function at all. The other programs do not seem to have an issue, they also don't do anything online anyways (for all intensive purpose).

Between similar looking domains, dlls, and comparing several sets of binaries, its quite possible I mixed something up somewhere. I really want to drill down to see if/what is getting blocked and finding an easy but dyanmic way to route http traffic. 

There's a MUCH easier way to go about this. 
- Step 1: don't be an idiot, and when replacing strings use UTF-16 LE. I dumbed on this originally. 
- Step 2: just replace the string in the binary. Seems to work just fine tearing it out and stuffing a new one in. Just, keep the char count equal to or less. 
Will post a better patch once I dig down a little more. As of now I have sucessfully blocked all calling home things, without breaking any update function.

for the time being, there's a script just to patch out over the 2 domains on any input binary
- gsMRI_strReplace.py

### update /end

Putting all of this under one repo for informations. 
Documented for entertainment
Applies to MRI BDE v. 5.11.0.7 (5.11.0.6 listed on indexes is probably really 0.7)
Patch(es) I feel should work for many versions.

### ok....breaking down by 3 dlls.
- GSCommon.dll ("Expiration" dates)
- ~~GSCore.dll ("Calling home ping")~~
- GSSkin.dll ("Skin walker ranch")

Click HERE to jump to the section you want. 


# GSCommon.dll
###### Because 2012 was disappointing.....
Excluding MRI.exe (kinda) GSCommon.dll is responsible for date checking. 

This isn't tuts4yuuuahhh crank dat

Jump the check, done. Don't bother 'patching' everything. 

Script to patch in the GSCommon dir.

![Image](https://github.com/whalelinguni/GeekSquadMRICrack/blob/main/GSCommonPatch.png?raw=true)


# GSCore.dll
This little dll went to market, and pings home. 

~~I \*think\* the way I patched this does not interfere with anything.~~
I thought wrong. See 09-30 update

The patch cuts out the call home portion when subsequent binaries are run. The only issue with this method is sometimes system updater may crash on first launch (Or it does not and I have some issue with my environment). Not the most elegant method, but I don't think this dll has been touched since like 2004.

Again, the rest of the binaries use GSCore for this. Nop it out, et no phone home.

Script to patch in the GSCore dir.

![Image2](https://github.com/whalelinguni/GeekSquadMRICrack/blob/main/GSCore-Ping-Patch-2.png?raw=true)


# GSSkin.dll
## Resource Inspection and Observations

### Edit: 09-30: As pointed out, I used 'color' a bit loose. The 'color' in the XML is for the text, shading, menu bars, etc. NOT the buttons etc. 

- Seems that LangID must be set to 1033 (United States) for it to operate correctly. (I think)
- Inspecting the 'STYLE XML' have found this appears to use 'SkinCrafter' for the GUI skin.
	- Note that in the XML there's a prefix defined of 'GS_'
	- Note that image resources are PNG not Bitmap (this will matter later)

### SkinCrafter
http://skincrafter.com/

The 'Style XML' contains layout information, sizing, color, and color gradients
- "Skins" can be found but are in the SkinCrafter .skf format.
	- If interested there's loads of skins on the SkinCrafter webpage under 'Galley'

I cannot get SkinCrafter to run correctly, atleast in Win10x64, trying to import the extracted XML results in a crash. Trying to import any skin downloaded also leads to a crash. If you decide to mess around with this, may want to spin up a Win7x86 vm or something. I did not go down this route.

I have not found a good way to extract the skincrafter information from a compiled dll.

## So how edit and change?

Since I am not SUPER interested in modifying the GUI, my intrest is mostly just in how the dll/skin operates, I took some shortcuts to make the process somewhat easier, but also somewhat limiting.

##### After some trial an error being lazy, this is mostly what I found:

Contained in the SkinCrafter SkinBuilder application are a few dlls. Each of the dlls have the compiled skin information within them. Since I am unable to extract everything needed to rebuild a .skf (also I have no idea how this is packed, nor care) 
I found it easiest to transplant the XML information from one of the dlls into the GSSkin.dll. 
Its much easier to edit the GSSkin.dll directly rather than trying to generate a replace it with a new one which may contain more elements for further customizing, but will break any referencing causing the gui not to load correctly. 
Since the XML information is just used for sizing, colors, etc, these should all apply correctly while keeping the referenced information that the dll needs in place. You're just limited on how much customizing you can do. 

For example; In 'System Updater', the icons in the main ribbon, I do not see where those are getting pulled from. I'm guessing the gsskin.dll must be referencing something else for this. 
If you break it by replacing the dll, while you now are able to edit/add more gui changes, you lose all that referenced data (Ribbon Icons). But as I said, I am not super interested in the GUI, so I didn't bother to go much further than this. 

#### In Short:
- Copy the style XML information from a compiled skincrafter dll and replace the xml data in the gsskin.dll
- do NOT forget to add the line at the top that defines the prefix of 'GS_' 
	- You can look at 'SILVER.XML' and 'SILVER-MOD-GS.XML' to see this.
	- I simply added the prefix information and changed the name back to 'Geek Squad' although I don't think that the naming matters.

After doing this, launching any of the exes that use the gsskin.dll, you should have somewhat of a new skin.

#### And/Or
- You can edit the RGB colors directly in the XML. This is very tedious and boring to do by hand.

Other resources are as straiht forward as any other compiled binary you want to edit. Changing strings,
Changing icons/logos/bitmaps etc.

More or less that be it.


## Further things doing roadmap:
Would like to just hook the api and re-route all traffic to geeksquadcentral.com to /dev/null or your own server. A quick look at traffic suggests it would be rather trivial to "emulate" the backend. I guess... you could save your notes on your own server? Kinda pointless... but thats my jam. I may or may not ever do this. 

I have little interest in any of this in general. 
