# but_i_dont_want_to_install_an_authenticator_app_on_my_cell_phone

Do you hate cell phones? Me too! Do you hate apps? Me too! After hours of rage at being
locked out of a cryptocurrency account because I refuse to install an authenticator app
on my phone, I wrote my own.

## how authenticators work

When you go to your favorite website and set up two-factor authentication with an authenticator app,
the site displays a QR code. Your authenticator scans that app and decodes it into a URI (universal
resource somthing-or-other). That URI contains a few things:

- protocol header "otpauth://"
- the type "totp" (time-based one-time password) or "hotp" (counter-based (the "h" is for "HMAC"))
- the name of the thing that is being protected. I will call this the "service". It might or might not contain useful information. Sometimes it contains your email address or login name, but not the name of the website. Sometimes it contains more information.
- a secret. This is the important thing.
- (optional) the name of the issuer of the URI. This should be the name of the website.
- (optional) the hashing algorithm (defaults to SHA1)
- (optional) the length of the one-time passwords (OTP) (defaults to 6)
- (optional) the period of time for which the OTP is valid (defaults to 30 seconds)
- HOTPs have a counter and do not have a period

By scanning that QR code and grokking the URI, the authenticator app drinks in that tasty "secret", which is the important thing to know about.
That secret has to match the one that the webserver has stored in association with your login credentials. Next, the authenticator
generates a OTP from the secret and the current time. That OTP is a 6-, 7-, or 8- digit number that you feed back to the website to
prove that you received the correct secret. The webserver stores a copy of that secret along with your login credentials.
Your authenticator app stores the secret locally.

When you return to the site later, it asks you for a new OTP, but does not display a QR code. The authenticator app
generates a OTP from the secret that it stored earlier and the current time. You send that OTP back to the server, which
calculates its own OTP. If they match, then you are validated. The authenticator does not communicate directly with the webserver.

## requirements

This authenticator requires...

- Python version 3
- pyscreenshot (PIL ImageGrab() does not work on linux for older versions)
- EasyProcess (needed by pyscreenshot)
- pyzbar
- python cryptodome
- 
## how to use this authenticator

Change the script to be executable. Then if you run it with no command-line arguments, and if there is a QR code visible
on your desktop, it should scan that QR code and store the secret therein, as well as spit out the first OTP.

Secrets are stored in file `~/.authentications`

When you add a command-line argument, it will seek a service that matches the argument in its storage. If it finds one,
it generates and outputs a new OTP.

## things that should be done

If you would like to help, there are some things that should be done to this project. Feel free to send patches or pushes or whatever they are called.

- a GUI. It should be a pretty one. It would nice if it could select the region of the desktop to scan. It should be independent of window manager, but if you want to write one for GNOME or KDE, then please do. But I would like one based on GTK+ so that it can work anywhere.
- convert the storage to something standard, like CSV. I don't believe that the data is complicated enough to justify a true database, but I am willing to listen to arguments.

## disclaimer

I do not claim to have written this script well. I do not even claim that it will work.
YOU USE IT AT YOUR OWN RISK. If you get locked out of your financial accounts and can't pay your rent, don't call /me/.
If it gains self-awareness and embarks on a campaign of world domination, don't look at me--I'l be on the first
Space-X flight outta here.

## no, I did not use pyotp

There is also a project called pyotp that provides a library for HOTP and TOTP. I didn't
use it because I only needed one function (and I wrote one that is shorter).
But it is a very fine project, and I learned a lot by reading its code.

## references

http://www.rfc-editor.org/rfc/rfc6238.txt

http://github.com/google/google-authenticator/wiki/Key-Uri-Format
