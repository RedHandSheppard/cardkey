# cardkey
usb keyboard, encrypted passwords/notes.
its probably got bugs, please feel free to critique, im new to all this.

boots to a usb keyboard mode with the screen off.
it beeps once if no sd is found, twice if it finds the sd card.
if no sd is found it can unly be a usb keyboard, the menus wont even trigger.
if an sd is found, hitting fn + ctrl will launch the vault password prompt(Default: m5pass).
the prompt leads to the main menu:

!! New Vault Pass !!
-> New Menu Color <-
-> Notes <-
-> Passwords <-

new vault pass will prompt you for a new pass then confirm the new pass, it tells you if it fails but not if it suceeds.
the other three options lead to menus of their own, shown below. All menus scroll when there are more entries than screen space.

-> New Menu Color <- :

<- Main/Colors
Hex COLOR (0xF800)
SET TO: RED
SET TO: YELLOW
SET TO: BLUE
SET TO: GREEN
SET TO: ORANGE
SET TO: PURPLE

menus are drawn in black white and red by default, but this menu lets you set the red to be any color you want with hex or to some defaults.
hex color takes hex and converts it to RGB565.

-> Notes <- :

<- Main/Notes          <- Main/Notes
-> ADD NOTE <-         example1
                       example2
                       -> ADD NOTE <-

this menu lists saved notes by title, clicking the title takes you to a note edit menu. the top entry is just a back button named to act as a title for the current menu.
the add note entry will prompt you for a title then return to this menu for simplicity.

the note edit menu :

<- Main/Note/Edit
TITLE: example
BODY: example text
!! DELETE ENTRY !!

this menu lets you go back, edit the title or the body, lets you delete the entry.
editing the body takes you to a fullscreen note editor. fn + enter saves, fn + ` exits without saving.

-> Passwords <- :

<- Main/Passwords      <- Main/Passwords
-> ADD ENTRY <-        example1
                       example2
                       -> ADD ENTRY <-

this menu lets you view saved passwords by their lable and delete entries.
clicking an entry lable takes you to the pass edit screen.

the pass edit screen :

<- Main/Pass/Edit
LABLE: example
USER: usr
PASS: XXXXXXXXX
!! GENERATE PASS !!
!! DELETE ENTRY !!

this menu lets you edit the lable username and password saved to this entry, pressing fn + enter will send data over usb as keyboard input.
generate pass does what it describes, it does not confirm befor overriting the password so !!

all menus should time out after 15 seconds of inactivity to relock the vault for security. the saved notes and passwords should be AES encrypted, hence the delay when saving/loading(half second)
