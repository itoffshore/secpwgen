# secpwgen
The sources for [secpwgen](http://linux.die.net/man/1/secpwgen) authored by [Željko Vrba](http://zvrba.net/)

It is [recommended](https://lwn.net/Articles/525459/) to run **both** Entropy Daemons:[`haveged`](https://wiki.archlinux.org/index.php/Haveged) **AND** [`rng-tools`] (https://fedoraproject.org/wiki/Features/rngd_default_on).

[Diceware phrases](http://world.std.com/~reinhold/diceware.html) need to consist of [7 - 8 words to be unbreakble by current technology](http://arstechnica.com/information-technology/2014/03/diceware-passwords-now-need-six-random-words-to-thwart-hackers/).

All 3 applications exist as packages in [Alpine Linux](http://pkgs.alpinelinux.org/packages?package=secpwgen&repo=all&arch=x86).
