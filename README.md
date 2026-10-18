# Notes: secure daily brief app for HRA

A plain-looking "Notes" app. You type a **title** and a **message**, choose **Send as** (Email, Text message, Signal, WhatsApp, Garmin Messenger, or Text document), and tap **Send**. The note is encrypted on your device before it is handed to that channel, so the only thing that leaves your device is scrambled text. The other person opens it in the same app with the same key.

It works on iPhone, iPad, Mac and Windows PCs, online or offline. It has no account and no server, it saves nothing on the device, and it never connects to the internet.

## How to use it

1. **Agree a key in person.** The app opens on the **Key** screen with a 3-step guide. Tap **Generate key** to get 7 simple words (for example `pink opinion rich lobster produce thank poet`). Write them down and hand them over face to face. Never send the key in the same channel as the notes. Both people type the words and tap **Use key**. Capitals, extra spaces and dashes don't matter, and each word can be shortened to its first four letters. If a word is misspelt, the app says so while you type.
   - **Check you have the same key.** After **Use key**, the app shows a **check code** such as `always · cook · 30`. Read it to each other in person or on a call you trust. Same code means same key. A different code means one of you typed the key differently.
2. **Write.** On **New**, fill in Title and Note, choose **Send as**, and tap **Send**.
   - **Email / Text message / WhatsApp**: the app opens with the encrypted note filled in. You choose the contact and press send.
   - **Signal**: the share sheet opens, so pick Signal. On a computer the note is copied and you paste it into Signal.
   - **Garmin Messenger**: short notes fit in one 160-character message. Longer notes are split into numbered parts (`1/2 …`, `2/2 …`), and you send each part.
   - **Text document**: saves `note-YYYY-MM-DD.txt` holding the encrypted note.
   - A **Copy** (and **Share**) button always appears under the note as a fallback.
3. **Read.** On **Open**, paste what you received (all Garmin parts, in any order) or tap **Open file**, then tap **Open**. If the note was made with a different key, the app tells you and shows both check codes. Notes made with the first version of the app still open.
4. **Clear** wipes the screen. **Lock now** wipes the key. The key also wipes itself after 10 minutes idle or 2 minutes in the background, and the screen blurs in the app switcher.

## Installing it

The app is the files in this folder. Nothing in them is secret: the security comes from the key, which never leaves your hands.

**Mac or Windows PC (simplest, fully offline):** copy the folder (or download it from the Google Drive folder "Notes app" and unzip it) anywhere, for example to `Documents`, and double-click `index.html`. Bookmark it. It works with no connection.

**iPhone and iPad:** iOS only runs web apps from a web address, so the folder has to be put on any HTTPS host once. Google Drive cannot do this. After that you install it to the Home Screen and it runs offline.
1. Upload the folder to a static host. Free options are GitHub Pages, Cloudflare Pages, or Netlify Drop (drag the folder onto app.netlify.com/drop). Pick a dull site name.
2. Open the address in **Safari**, tap **Share → Add to Home Screen**, and keep the name "Notes".
3. Open it once from the Home Screen while online. From then on it works in airplane mode.

The same address also works on Mac (Safari: **File → Add to Dock**) and on Windows (Edge or Chrome: **Install app**).

## How secure is it

**The encryption.** Title, message and time are encrypted together with **AES-256-GCM**, using the browser's built-in, audited crypto (WebCrypto). The key is stretched with **PBKDF2-SHA-256 at 600,000 rounds** with a random salt, which makes guessing the key slow. Every note gets a fresh random nonce. GCM also detects tampering: a changed, truncated or wrong-key note simply will not open. The app's security policy stops it from loading any outside code or contacting any server.

**What each channel adds or leaks.** The note is protected on every channel. The channel still decides who can see *that* you sent something, to whom, and when.

| Channel | Channel's own protection | What an observer can still see |
|---|---|---|
| Signal | End-to-end encrypted, minimal metadata. **Best choice.** | Very little |
| WhatsApp | End-to-end encrypted | Who you message and when (Meta) |
| iMessage (Text, blue bubble) | End-to-end encrypted | Who and when (Apple) |
| SMS (Text, green bubble) | None | Carrier sees sender, recipient, time |
| Email | Usually only server-to-server TLS | Providers see sender, recipient, time, subject ("Note" + date) |
| Garmin Messenger | Satellite link, Garmin servers | Garmin sees sender, recipient, time, and your GPS position if tracking is on |
| Text document | Whatever stores or carries the file | File name and date |

Even on the weakest channel, someone who intercepts the note sees only a block of random-looking characters.

**The limits you should know.**
- **The key is everything.** A weak key can be guessed offline. Use **Generate key** (7 words, 77 bits, each guess slowed by 600,000 rounds) or a long phrase of 6 or more random words. Change it if you think it was seen, and use a different key for each person or team. Never store the key in Google Drive or email.
- **A compromised device beats any encryption.** Spyware or someone looking over your shoulder sees the note before it is encrypted. Keep the phone updated, use a strong passcode, and consider **Lockdown Mode** on iPhone in high-risk places.
- **Copies can linger.** The sent ciphertext stays in your Sent folder, chat history or Files, which is harmless without the key. Your keyboard's predictive text may still learn words you type, so you can turn off Predictive Text if that matters.
- **The check code links notes.** Each note carries a short key ID so the app can tell you about a wrong key. Someone who collects several of your notes can tell they were made with the same key, but not what the key is or what the notes say.
- **Encrypted text can look unusual.** It won't reveal content, but at a checkpoint someone may ask what it is. Deleting sent notes from chat history reduces that.
- **The app cannot press "send" for you.** Browsers are not allowed to send messages on their own, so you always choose the recipient and press send yourself. That also prevents a note going to the wrong person by accident.

## Files

`index.html`, `app.js` (interface), `crypto.js` (encryption), `words.js` (the standard 2,048-word BIP-39 list used for keys and check codes), `style.css`, `sw.js` (offline cache), `manifest.webmanifest` and the icons. `notes-app.zip` holds all of them.

If you change any file, bump `VERSION` in `sw.js` so installed copies pick up the change.
