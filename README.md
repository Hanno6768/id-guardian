# SudaGuardian

#### Video Demo: [HERE](https://youtu.be/D8iNZhQ-2T0)

#### Description:

The idea for SudaGuardian was inspired by the recent crises in Sudan. During instability or conflict, many citizens are at risk of losing their physical documents. These documents are essential for education, travel, banking, healthcare, and government services. Losing them makes a difficult situation even harder .

**SudaGuardian** is my attempt to design a responsive web application that works as both a digital identity system and a digital document wallet. Its purpose is to protect citizens' identity information even when they can't access their physical files.

## How users interact

- A normal user can register, upload documents, verify their email, log in, view dashboard, check documents, see history, and update their profile.
- A reviewer can use the review queue to inspect pending users and take actions on pending documents.
- An admin could access the administrative pages such as the admin dashboard, manage users, and the system settings.

## Files

1. `app.py` is the main Flask application file. It defines the routes for pages such as `/register`, `/login`, `/user-dashboard`, and `/my-profile`.
2. `extensions.py` separates the Flask-Mail extension so it can be imported cleanly.
3. `helpers.py` contains the helper functions and constant variables used across the project, including `STANDARD_DOCUMENTS`, `generate_new_filename()`, `@roles_required()` decorator, and `send_mail()`.
4. `models.py` contain Python classes that represent users, documents, and pending verification requests, and it is the place where most of the database queries are executed. For example `User` that handles the existing verified user, while `PendingUser` represents a user who has registered but is not yet approved by a reviewer.
5. `SudaGuardian.db` is the database where all the tables are located and includes `users` table, `documents` table, and `history` table.
6. `requirements.txt` lists the needed packages to run the project.
7. The `templates/` folder contains the HTML for pages and emails. For example, `register.html` handles account registeration, `login.html` handles login, and `verify_email.html` which handles email verifiacation.
8. The `static/` folder which contains the JavaScript, CSS, images, user uploads, and other frontend assets used to style the website.

## Design choices

### Role-based access:

- One of the most important design choices I made was separating the users into different roles: normal users, reviewers, and admins. This made the application more realistic because not all users should access all pages or have the same permissions.

- I also implemented role-based access control using a custom `@roles_required()` decorator. This decorator accepts specific roles as arguments ('user', 'admin', 'reviewer') and blocks unauthorized access.

### Hashing and encryption:

- Another important choice was hashing the National ID number instead of storing it as plain text in the database. Since this project deals with identity information, I wanted the design to show awareness of privacy and security.

- However, I later faced another problem: some parts of the application needed to display the National ID number to admins and reviewers. To overcome this, I decided to store an encrypted version of the National ID number as well, so it could be decrypted when needed.

## Main Features:

### Sharing Document by QR code:

- SudaGuardian includes a QR feature for approved documents. When a user uploads a document and the document is approved by a reviewer, the system generates a unique token connected to the document. That token is sent to the frontend and rendered as a QR code.

> [!NOTE]
> This feature makes the project more practical because a verified citizen could present important documents to government officials through scannable code without needing to carry the original physical papers at all.

### Automated Emails:

- SudaGuardian also includes automated emails for important account and verification actions. The system sends automated emails (some may include verification links) when users register, password setup or reset links when users need account access, and notifications emails when a document is approved, rejected, or needs correction.

## How to Test the Application

1. To test the application, run the Flask app by running `python3 app.py` on the project folder, then open the browser.

2. A new user can register from the registration page by entering their personal information on the `register` page:
   - Full name
   - Birthdate
   - Phone number
   - Valid email address (for email verification)
   - Username
   - 11-digit national ID number
   - Supporting document for identity verification

3. Verify your email address: - Open your inbox - You will find an email whose sender is `sudaguardian.dev@gmail.com`. - Click on the _"Verify Email Address"_ button

   > [!NOTE]
   > This email is valid for 30 minutes

4. Log in as a reviewer:
   - Go to the `login` page
   - Username: `reviewer1`
   - Password: `testtest`

5. Go to the `reviewer-queue` page:
   - Under the Pending Users tab, search for the user you registered, then click on the eye icon.
   - Here all the pending user's information can be found as well as the supporting document.
   - Click on the _"Approve Access"_ button, then confirm by clicking on the _"Approve User"_ button on the modal that pops up.

6. Log out of the reviewer account by heading to the `my-profile` page.

   > [!IMPORTANT]
   > To prevent session conflicts, log out before switching accounts

7. Set your password: - Open your inbox - You will find a new email - Click on the _"Set Secure Password"_ button - You will be directed to the `set-password` page - Type a password and confirm it - You will be automatically logged in to your account

   > [!NOTE]
   > This email is valid for 24 hours

8. Upload a file:
   - Open the `my-documents` page
   - Click the _"Upload"_ button on one of the documents placeholders. (for example, Passport)
   - Choose the document you want to upload and agree to the declaration
   - Click on the _"Submit For Review"_ button

9. Log out of the user account by heading to the `my-profile` page.

   > [!IMPORTANT]
   > To prevent session intervention

10. Approve document:
    - Log in as reviewer again
    - Open the `review-queue` page under the Uploaded documents tab
    - Find the document
    - Click on the eye icon
    - Click _"Approve Document"_ button and confirm

11. Try QR code document sharing:
    - Log in as the user again using the username and password set in step 7
    - Open the`my-documents` page
    - Passport should show a verified badge and an SVG should appear on the document card
    - Click on the _"Show Details"_ button
    - You should be able to see the document you uploaded and toggle between the document and the QR code
    - Log in as a reviewer again, then scan the QR code
    - You will be directed to the "/my-documents/verify_document" page where you can see the user's uploaded document

> [!TIP]
> For testing the admin side of the project, an existing admin account can be used:
>
> - Username: `admin1`
> - Password: `testtest`</br>
>   When in an admin session, you can access the admin dashboard, manage users, view system settings and inspect parts of the verification system that normal users cannot access.

## Challenges and Lessons Learned

One of the most challenging parts of this project was setting up the Python classes and understanding how will they work with Flask-Login as well as the databse at the same time. At first, it felt almost impossible looking at the amount of work I had to do.

The lesson I learned the hard way is that planning is a major part of the work. SudaGuardian took months of learning, coding, testing, and debugging. It became much larger that I first expected, that made finishing it even more meaningful. In the future, I would like to keep improving the project to turn it into a real-world platform.

Nothing is impossible!

This was CS50 :trollface: