CryptoHash Analyzer - Dark Student UI Version
=============================================

How to run:
1. Extract the project folder.
2. Open terminal/cmd inside the folder.
3. Run: python main.py

Main features:
- Login and register with local user storage in data/users.json
- Hash with encryption, with verification on the same page
- Hash only, with verification on the same page
- Text/hash analysis in hashing pages
- Copy hash buttons for generated hashes
- HMAC / Message Authentication Code with copy button
- File hashing using SHA-256, SHA-512, and SHA3-256 with copy buttons

Notes for discussion:
- Hashing is one-way and is not encryption.
- The encryption options are educational examples.
- MD5 and SHA-1 are included for comparison only.
- File hashing can be used for integrity checking by comparing old and new file hashes.


Final screen fix:
- The program opens maximized on Windows.
- Feature pages use stacked input/result sections so boxes fit laptop screens.
- The main content area supports mouse wheel and touchpad scrolling.
