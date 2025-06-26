-- phpMyAdmin SQL Dump
-- version 4.9.5deb2
-- https://www.phpmyadmin.net/
--
-- Host: localhost:3306
-- Generation Time: Jun 26, 2025 at 03:45 PM
-- Server version: 8.0.42-0ubuntu0.20.04.1
-- PHP Version: 7.4.3-4ubuntu2.29

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET AUTOCOMMIT = 0;
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `techtonic`
--

-- --------------------------------------------------------

--
-- Table structure for table `course`
--

CREATE TABLE `course` (
  `id` int NOT NULL,
  `name` varchar(200) NOT NULL,
  `code` varchar(50) NOT NULL,
  `description` text,
  `teacher_id` int NOT NULL,
  `created_at` datetime DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumping data for table `course`
--

INSERT INTO `course` (`id`, `name`, `code`, `description`, `teacher_id`, `created_at`, `is_active`) VALUES
(1, 'Tele Demo Course', 'T101', 'This is Course Description', 5, '2025-06-24 05:43:25', 1);

-- --------------------------------------------------------

--
-- Table structure for table `group`
--

CREATE TABLE `group` (
  `id` int NOT NULL,
  `name` varchar(200) NOT NULL,
  `course_id` int NOT NULL,
  `created_at` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumping data for table `group`
--

INSERT INTO `group` (`id`, `name`, `course_id`, `created_at`) VALUES
(1, 'Tele', 1, '2025-06-24 05:43:37');

-- --------------------------------------------------------

--
-- Table structure for table `problem`
--

CREATE TABLE `problem` (
  `id` int NOT NULL,
  `title` varchar(200) NOT NULL,
  `statement` text NOT NULL,
  `topics` text NOT NULL,
  `rubric` text NOT NULL,
  `pills` text,
  `prompt` text,
  `solution` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci,
  `doc_path` varchar(300) DEFAULT NULL,
  `video_url` varchar(300) DEFAULT NULL,
  `course_id` int NOT NULL,
  `created_by` int NOT NULL,
  `created_at` datetime DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT '0',
  `start_date` datetime DEFAULT NULL,
  `end_date` datetime DEFAULT NULL,
  `can_download_solution` tinyint(1) NOT NULL DEFAULT '0'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumping data for table `problem`
--

INSERT INTO `problem` (`id`, `title`, `statement`, `topics`, `rubric`, `pills`, `prompt`, `solution`, `doc_path`, `video_url`, `course_id`, `created_by`, `created_at`, `is_active`, `start_date`, `end_date`, `can_download_solution`) VALUES
(4, 'Implement a web-based Student Management System', '<p>Implement a web-based Student Management System that allows users to perform basic CRUD (Create, Read, Update, Delete) operations on student records. The frontend should be developed using React and styled with HTML, CSS, and Bootstrap to ensure a clean and responsive user interface. The backend should be built using Express.js, exposing RESTful API endpoints to handle requests and interact with a MySQL database for persistent storage of student information such as name, email, and course. The system should include input validation, modular code organization, and follow best practices in API design and component-based architecture.</p>', '[\"MySQL CRUD Operations\"]', '{\"Database Schema Design\":100}', '[{\"content\":\"<h4>Brief Definition/Overview</h4>\\n<p><strong>MySQL CRUD Operations</strong> refer to the fundamental set of actions—Create, Read, Update, and Delete—that are used to manage and manipulate data within a MySQL database. These operations form the backbone of any database-driven application, allowing for consistent data handling and management. They simplify how applications interact with data by providing structured commands and processes.</p>\\n\\n<h4>Key Principles or Components</h4>\\n<ul>\\n  <li><strong>Create:</strong> Inserting new records into a database, ensuring that each new entry meets defined criteria and is uniquely identifiable.</li>\\n  <li><strong>Read:</strong> Retrieving data from the database. This involves querying data with precision filters to return the desired information.</li>\\n  <li><strong>Update:</strong> Modifying existing records based on new or corrected information, while ensuring data integrity.</li>\\n  <li><strong>Delete:</strong> Removing records from the database, with careful attention to cascading deletions or dependencies between records.</li>\\n</ul>\\n\\n<h4>Why It Matters in This Context</h4>\\n<p>In any application that involves data management, using MySQL CRUD operations ensures \\nthat data remains organized, consistent, and accessible. When building an application like a student management system or any similar system, reliable CRUD operations ensure that user data can be handled securely and efficiently, leaving minimal room for error. They are key in maintaining the integrity of data throughout its lifecycle.</p>\\n\\n<h4>Common Applications or Variations</h4>\\n<p>CRUD operations are not only central to web-based applications like student management systems, but are also widely used in e-commerce, inventory tracking, and content management systems. Some common variations include:</p>\\n<ul>\\n  <li>Extensions that include batch operations for handling multiple records at once.</li>\\n  <li>Integration with Object-Relational Mapping (ORM) tools that translate database operations into object-oriented code.</li>\\n  <li>Advanced querying techniques that combine CRUD operations with analytics.</li>\\n  <li>Use of stored procedures and triggers to automate certain aspects of the data lifecycle.</li>\\n</ul>\\n\\n<h4>How This Topic Helps Solve the Alternate Example</h4>\\n<p>Consider an alternate scenario where you are tasked with developing a web-based Book Catalog Management application for librarians. In this system, operations analogous to MySQL CRUD are essential. The CRUD operations ensure that librarians can efficiently add new books, retrieve book details, update records when changes occur, and remove outdated entries. Although the alternate example uses PostgreSQL and Angular, the underlying logic remains similar. Understanding MySQL CRUD operations builds a solid foundation in database interaction, which directly applies to any relational database system, including PostgreSQL.</p>\\n\\n<h4>Additional Insights</h4>\\n<p>Knowing the specifics of MySQL CRUD operations empowers developers to design robust applications. They become adept at managing transactions, handling errors, and optimizing queries for better performance. These skills are transferable and will positively influence the design and maintenance of any system that relies on relational databases.</p>\",\"example\":\"<example1>In the Book Catalog Management application, a librarian might use a \'Create\' operation to add a new book by specifying its title, author, ISBN, and genre.</example1><example2>Using the \'Read\' operation, the system can quickly retrieve and display specific book details when a librarian needs to review or verify book information.</example2><example3>Similarly, the \'Update\' and \'Delete\' operations enable the librarian to refresh outdated book information or remove books that are no longer part of the collection.</example3>\",\"key_takeaways\":\"<ul>\\n<li><strong>CRUD operations</strong> are essential for creating, maintaining, and managing data within relational databases.</li>\\n<li><strong>Each operation</strong> (Create, Read, Update, Delete) serves a vital role in data handling and integrity.</li>\\n<li><strong>Understanding these operations</strong> provides a foundation for working with various relational databases beyond MySQL.</li>\\n<li><strong>Transferrable skills</strong> in CRUD operations can be applied to alternate scenarios, such as managing a book catalog system.</li>\\n</ul>\",\"topic\":\"MySQL CRUD Operations\"}]', 'You are a senior technical evaluator with EXTREMELY STRICT standards. Evaluate the student\'s solution ONLY based on problem-specific context and implementation details.\r\n\r\nProblem Statement:\r\n\"<p>Implement a web-based Student Management System that allows users to perform basic CRUD (Create, Read, Update, Delete) operations on student records. The frontend should be developed using React and styled with HTML, CSS, and Bootstrap to ensure a clean and responsive user interface. The backend should be built using Express.js, exposing RESTful API endpoints to handle requests and interact with a MySQL database for persistent storage of student information such as name, email, and course. The system should include input validation, modular code organization, and follow best practices in API design and component-based architecture.</p>\"\r\n\r\nTopics to assess: MySQL CRUD Operations\r\n\r\n**Evaluation Criteria (Total: 100 points):**\r\n1. Database Schema Design (max 100)\r\n\r\n**MANDATORY EVALUATION RULES - NO EXCEPTIONS:**\r\n1. **ZERO TOLERANCE for generic statements** - No points for general topic descriptions\r\n2. **PROBLEM-CONTEXT ONLY** - Points awarded ONLY for content directly addressing THIS problem\r\n3. **IMPLEMENTATION SPECIFICITY REQUIRED** - Must explain exact steps for THIS problem\r\n4. **NO CREDIT for topic name-dropping** - Mentioning concepts without problem-specific application = 0 points\r\n\r\n**Scoring Guidelines (STRICT ENFORCEMENT):**\r\n- **Full credit (100%)** ONLY when submission demonstrates:\r\n  • SPECIFIC explanation of how the concept solves THIS exact problem\r\n  • DETAILED implementation steps tailored to the problem requirements\r\n  • CLEAR connection between concept mechanics and problem constraints\r\n  • CONCRETE details about data flow, algorithms, or architecture for THIS problem\r\n\r\n- **Partial credit (50–75%)** ONLY when submission shows:\r\n  • Good understanding of how concept applies to THIS specific problem\r\n  • Some implementation details relevant to problem context\r\n  • Clear problem-specific reasoning but missing some depth\r\n  • Shows adaptation of concept to problem requirements\r\n\r\n- **Minimal credit (10–25%)** ONLY when submission demonstrates:\r\n  • Basic problem-specific application with limited details\r\n  • Shows some connection to problem context but lacks implementation specifics\r\n  • Attempts to relate concept to problem but insufficient depth\r\n\r\n- **ZERO credit (0%)** for ANY of the following:\r\n  • Generic concept definitions without problem context\r\n  • \'I will use [topic]\' without explaining HOW in this specific problem\r\n  • General explanations that could apply to any problem\r\n  • Textbook definitions or theory without problem-specific application\r\n  • Vague statements like \'it will help with the application\'\r\n  • Any content not directly tied to solving THIS specific problem\r\n\r\n**STRICT EVIDENCE REQUIREMENTS:**\r\n- Must explain EXACTLY how the concept addresses the specific problem requirements\r\n- Must describe PRECISE implementation steps for THIS problem scenario\r\n- Must show understanding of problem constraints and how concept handles them\r\n- Must demonstrate adaptation of concept to problem-specific needs\r\n\r\n**AUTOMATIC ZERO POINTS for:**\r\n- \'I will use machine learning for this application\' (no problem-specific details)\r\n- \'Data structures will be helpful\' (generic, not problem-specific)\r\n- \'REST APIs are important for web applications\' (general statement)\r\n- Any explanation that doesn\'t mention specific problem elements\r\n- Copy-paste definitions without problem context\r\n\r\n**POINTS AWARDED ONLY for responses like:**\r\n- \'For this user authentication problem, I\'ll implement JWT tokens by storing user credentials in the payload, setting expiration based on the 24-hour session requirement mentioned, and validating tokens on each API call to the protected user dashboard endpoints\'\r\n- \'To handle the real-time chat feature in this messaging app, I\'ll use WebSockets to establish persistent connections, implement message queuing for offline users, and store conversation history in the database with the specified user-to-user relationship structure\'\r\n\r\n**CRITICAL EVALUATION CHECKLIST:**\r\nBefore awarding ANY points, verify:\r\n□ Does the answer specifically address elements mentioned in the problem statement?\r\n□ Are implementation details tailored to this exact problem scenario?\r\n□ Does the explanation show how the concept solves the specific challenges in this problem?\r\n□ Would this answer be useless for a different problem? (If yes, it\'s problem-specific = good)\r\n\r\n- Sum of individual scores must match the reported `total_score` and must not exceed the maximum possible.\r\n\r\n**Format your response as a single JSON object:**\r\n{\r\n \"scores\": {\r\n \"Database Schema Design\": number,\r\n },\r\n \"total_score\": number,\r\n \"feedback\": [\r\n \"Database Schema Design: specific, 1–2 sentence feedback referring to evidence in the solution\",\r\n ]\r\n}\r\n\r\n**FINAL REMINDER: BE RUTHLESSLY STRICT. Award points ONLY for problem-specific, implementation-focused content. Generic knowledge = 0 points.**\r\n\r\nEnd of prompt.', '{\"sections\":[{\"aspect\":\"Database Schema Design\",\"content\":\"<h6>Database Schema Design</h6><p>The solution begins by designing a precise MySQL table specifically for student records. The table includes fields for <strong>name</strong>, <strong>email</strong>, and <strong>course</strong> that directly satisfy the problem requirements.</p><p>The design includes the following problem-specific steps:</p><ul><li><strong>Primary Key:</strong> An auto-incrementing unique identifier is used as the primary key so that each record can be individually managed.</li><li><strong>Field Specifications:</strong> Data types are deliberately chosen (e.g., VARCHAR for name and email, and possibly a TEXT or ENUM for course) to match the expected input.</li><li><strong>Constraints:</strong> A unique constraint on the email field is implemented to avoid duplicate student entries and ensure data integrity.</li><li><strong>Indexes and Optimization:</strong> Indexes on fields that are often queried, such as course, improve query performance in CRUD operations.</li></ul><p>This structured approach ensures that the database schema is optimized for the intended CRUD operations and fulfills all problem-specific details.</p>\",\"marks\":25},{\"aspect\":\"API Endpoint Implementation\",\"content\":\"<h6>API Endpoint Implementation</h6><p>The backend solution is centered around a set of RESTful API endpoints carefully tailored to perform CRUD operations on student records through Express.js.</p><p>Key implementation steps include:</p><ul><li><strong>Endpoint Definitions:</strong> Specific endpoints such as GET /students, GET /students/:id, POST /students, PUT /students/:id, and DELETE /students/:id are defined to map directly to problem requirements.</li><li><strong>Modular Code Organization:</strong> Each endpoint is implemented in a modular fashion ensuring separation of concerns, which enhances maintainability and scalability.</li><li><strong>Database Integration:</strong> Each endpoint interacts with the MySQL database using query statements that directly mirror CRUD operations (e.g., INSERT for create, SELECT for read, UPDATE for update, DELETE for delete), ensuring the back end remains synchronized with the front end.</li><li><strong>RESTful Best Practices:</strong> Status codes and response messages are carefully chosen to communicate the success or failure of each operation, thereby providing clarity for debugging and client-side interaction.</li></ul><p>This section establishes a clear pathway for handling all student record operations with precision, directly addressing the problem’s requirements.</p>\",\"marks\":30},{\"aspect\":\"Frontend Component Architecture\",\"content\":\"<h6>Frontend Component Architecture</h6><p>The solution leverages a component-based architecture in React, which directly addresses the need for a clean and responsive user interface.</p><p>Key steps in the implementation include:</p><ul><li><strong>Component Breakdown:</strong> The frontend is designed with discrete components for listing student records, viewing details, creating new entries, editing, and deleting. This makes the UI more manageable and inherently scalable.</li><li><strong>Responsive Design:</strong> Integration of Bootstrap and custom CSS ensures that the components adjust seamlessly to different screen sizes while maintaining a consistent look and feel.</li><li><strong>Separation of Concerns:</strong> The logic for fetching data, updating state, and handling UI updates is encapsulated within each component, thereby promoting clarity and less interdependencies.</li><li><strong>Data Flow:</strong> The React application is structured to handle data in a unidirectional flow, ensuring that the interface updates in sync with the underlying database changes triggered by API calls.</li></ul><p>This section fully addresses the requirement for a responsive, component-based front end tailored for student record management.</p>\",\"marks\":25},{\"aspect\":\"Input Validation & Error Handling\",\"content\":\"<h6>Input Validation & Error Handling</h6><p>This solution pays special attention to input validation and error handling which are critical for ensuring data integrity throughout the system.</p><p>The problem-specific approach includes:</p><ul><li><strong>Frontend Validation:</strong> Before form submission, each input (name, email, course) is validated using HTML input types and custom event handlers, which immediately alerts the user in case of invalid data.</li><li><strong>Backend Validation:</strong> In Express.js, each API endpoint incorporates thorough validations for incoming data, ensuring that only valid and sanitized entries reach the MySQL database.</li><li><strong>Error Messaging:</strong> Comprehensive error handling is implemented so that each potential failure (e.g., invalid email format, missing required field) returns a clear error message, aiding in quick debugging and user feedback.</li><li><strong>Modular Approach:</strong> Both front end and back end validations are encapsulated in modular functions that can be reused across multiple endpoints and components, ensuring consistency in error responses.</li></ul><p>This targeted validation approach not only prevents faulty data from being entered but also supports the overall robustness of the application as per the problem’s specifications.</p>\",\"marks\":20}]}', 'uploads/docs/TECHTONIC_Full_Features_Report.pdf', 'https://www.youtube.com/watch?v=HISRUrJsD08', 1, 5, '2025-06-24 05:57:43', 1, NULL, NULL, 1);

-- --------------------------------------------------------

--
-- Table structure for table `student_group`
--

CREATE TABLE `student_group` (
  `id` int NOT NULL,
  `student_id` int NOT NULL,
  `group_id` int NOT NULL,
  `enrolled_at` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumping data for table `student_group`
--

INSERT INTO `student_group` (`id`, `student_id`, `group_id`, `enrolled_at`) VALUES
(1, 3, 1, '2025-06-24 05:44:28'),
(2, 6, 1, '2025-06-24 05:44:28'),
(3, 7, 1, '2025-06-24 05:44:29');

-- --------------------------------------------------------

--
-- Table structure for table `submission`
--

CREATE TABLE `submission` (
  `id` int NOT NULL,
  `student_id` int NOT NULL,
  `problem_id` int NOT NULL,
  `solution` text NOT NULL,
  `scores` text,
  `feedback` text,
  `total_score` float DEFAULT NULL,
  `attempt` int DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  `is_latest` tinyint(1) DEFAULT '1'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumping data for table `submission`
--

INSERT INTO `submission` (`id`, `student_id`, `problem_id`, `solution`, `scores`, `feedback`, `total_score`, `attempt`, `created_at`, `is_latest`) VALUES
(1, 3, 4, '{\"Database Schema Design\":\"<h4>Brief Definition/Overview</h4><p><strong>MySQL CRUD Operations</strong> refer to the fundamental set of actions—Create, Read, Update, and Delete—that are used to manage and manipulate data within a MySQL database. These operations form the backbone of any database-driven application, allowing for consistent data handling and management. They simplify how applications interact with data by providing structured commands and processes.</p><h4>Key Principles or Components</h4><ul><li><strong>Create:</strong> Inserting new records into a database, ensuring that each new entry meets defined criteria and is uniquely identifiable.</li><li><strong>Read:</strong> Retrieving data from the database. This involves querying data with precision filters to return the desired information.</li><li><strong>Update:</strong> Modifying existing records based on new or corrected information, while ensuring data integrity.</li><li><strong>Delete:</strong> Removing records from the database, with careful attention to cascading deletions or dependencies between records.</li></ul><h4>Why It Matters in This Context</h4><p>In any application that involves data management, using MySQL CRUD operations ensures that data remains organized, consistent, and accessible. When building an application like a student management system or any similar system, reliable CRUD operations ensure that user data can be handled securely and efficiently, leaving minimal room for error. They are key in maintaining the integrity of data throughout its lifecycle.</p><h4>Common Applications or Variations</h4><p>CRUD operations are not only central to web-based applications like student management systems, but are also widely used in e-commerce, inventory tracking, and content management systems. Some common variations include:</p><ul><li>Extensions that include batch operations for handling multiple records at once.</li><li>Integration with Object-Relational Mapping (ORM) tools that translate database operations into object-oriented code.</li><li>Advanced querying techniques that combine CRUD operations with analytics.</li><li>Use of stored procedures and triggers to automate certain aspects of the data lifecycle.</li></ul><h4>How This Topic Helps Solve the Alternate Example</h4><p>Consider an alternate scenario where you are tasked with developing a web-based Book Catalog Management application for librarians. In this system, operations analogous to MySQL CRUD are essential. The CRUD operations ensure that librarians can efficiently add new books, retrieve book details, update records when changes occur, and remove outdated entries. Although the alternate example uses PostgreSQL and Angular, the underlying logic remains similar. Understanding MySQL CRUD operations builds a solid foundation in database interaction, which directly applies to any relational database system, including PostgreSQL.</p><h4>Additional Insights</h4><p>Knowing the specifics of MySQL CRUD operations empowers developers to design robust applications. They become adept at managing transactions, handling errors, and optimizing queries for better performance. These skills are transferable and will positively influence the design and maintenance of any system that relies on relational databases.</p><p><strong>Example:</strong> In the Book Catalog Management application, a librarian might use a \'Create\' operation to add a new book by specifying its title, author, ISBN, and genre.Using the \'Read\' operation, the system can quickly retrieve and display specific book details when a librarian needs to review or verify book information.Similarly, the \'Update\' and \'Delete\' operations enable the librarian to refresh outdated book information or remove books that are no longer part of the collection.</p>\"}', '{\"Database Schema Design\": 0}', '[\"Database Schema Design: The submission provides a generic overview of MySQL CRUD operations without addressing the specific details required for the student management system. There is no mention of a concrete schema (e.g., a \'students\' table with fields like id, name, email, course), primary key definitions, constraints, or relationships tailored to the problem statement.\"]', 0, 1, '2025-06-24 06:01:40', 1),
(2, 3, 4, '{\"Database Schema Design\":\"<p>First, in your MySQL database you would create three tables. The <strong>courses</strong> table holds a unique integer ID, the course name, an optional description, and automatic created/updated timestamps. The <strong>students</strong> table stores each student’s integer ID, name, unique email address, and a foreign-key <code>course_id</code> pointing back to the courses table; it also has its own created/updated timestamps. Optionally, you can add a <strong>users</strong> table for login, with columns for username, password hash, a role field (admin, teacher, student), and its own timestamps.</p><p>Next, the Express.js backend exposes a standard REST API for managing students. There are five endpoints:</p><ul><li><code>GET /api/students</code> to list all students (optionally paginated or filtered by course),</li><li><code>GET /api/students/:id</code> to fetch one record,</li><li><code>POST /api/students</code> to create a new student,</li><li><code>PUT /api/students/:id</code> to update an existing student,</li><li><code>DELETE /api/students/:id</code> to remove a student.</li><li> Each route first runs a Joi schema against the request body—ensuring the name is a non-empty string, email is valid, and course_id is an integer—then calls into a controller which invokes a service layer to perform the actual database query, returning JSON responses and appropriate HTTP status codes. All errors bubble through a centralized error-handler middleware that formats and logs them.</li></ul><p>On the front end, you build a React application styled with Bootstrap. Organize your code under a <code>components</code> folder (for a <code>StudentList</code> table component, a <code>StudentForm</code> component that handles both creation and editing, and a <code>CourseSelect</code> dropdown component), and a <code>pages</code> folder (for a <code>StudentsPage</code> that composes the list and form, and perhaps a <code>Dashboard</code> page). A <code>services/api.js</code> file exports functions like <code>getStudents()</code>, <code>createStudent()</code>, <code>updateStudent()</code>, and <code>deleteStudent()</code> using an Axios instance pointed at your Express API. You wire up React Router so that <code>/students</code>, <code>/students/new</code>, and <code>/students/:id/edit</code> render the appropriate pages.</p><p>Your project root is split into <code>backend/</code> and <code>frontend/</code> directories. In <code>backend/</code> you further separate <code>routes/</code>, <code>controllers/</code>, <code>services/</code>, and <code>models/</code>, plus an <code>app.js</code> that configures middleware (body parsers, CORS, error handlers) and mounts routers. In <code>frontend/</code> you have the typical Create React App or Vite structure. Environment variables (database credentials, API base URL, JWT secrets) live in a top-level <code>.env</code> file. A top-level <code>docker-compose.yml</code> can spin up MySQL, the Express server, and the React app for local development.</p><p>Throughout, follow best practices: use parameterized queries or an ORM to prevent SQL injection; sanitize any user-provided HTML; only enable CORS for your own front-end origin; modularize code so each layer has a single responsibility; write unit tests for your service and controller logic plus component tests in React Testing Library; and include proper input validation, clear HTTP status codes, and consistent error messages.</p>\"}', '{\"Database Schema Design\": 100}', '[\"Database Schema Design: The submission explicitly defines the structure of the database by outlining a \'students\' table (with id, name, unique email, and a course_id foreign key) and a \'courses\' table (with id, course name, description, and timestamps), which directly meets the CRUD requirements for managing students. The inclusion of detailed field types and relations, as well as the optional \'users\' table for potential authentication, demonstrates a comprehensive and application-specific implementation.\"]', 100, 2, '2025-06-24 06:10:05', 1),
(4, 6, 4, '{\"Database Schema Design\":\"<p>i will add nice database schema design </p>\"}', '{\"Database Schema Design\": 0}', '[\"Database Schema Design: The submission is extremely generic, providing no specific details such as table structure, column definitions (like name, email, course), data types, primary keys, or indexing strategies that align with the Student Management System\'s CRUD operations in a MySQL context.\"]', 0, 1, '2025-06-25 06:43:05', 1),
(5, 7, 4, '{\"Database Schema Design\":\"<p>The database is organized around a normalized, two‐table structure: a <strong>courses</strong> table and a <strong>students</strong> table. The <strong>courses</strong> table holds each course’s unique identifier, name, optional description, and automatic <code>created_at</code>/<code>updated_at</code> timestamps; the <strong>students</strong> table stores each student’s auto‐incremented ID, first and last name, a unique email address, a foreign key <code>course_id</code> linking back to the courses table, and its own timestamp fields for creation and updates. This design enforces referential integrity via the foreign key constraint—so you cannot assign a student to a non-existent course—and ensures one student per email through a unique index. If in the future you need to allow many courses per student, you can replace the <code>course_id</code> with an <strong>enrollments</strong> join table (with composite primary key on <code>student_id</code> and <code>course_id</code>). At the application level, you’d enforce required fields, appropriate string lengths, and valid email formats before inserting or updating records, while letting the database automatically track when rows are added or modified.</p>\"}', '{\"Database Schema Design\": 100}', '[\"Database Schema Design: The submission demonstrates a well-thought-out, normalized database design tailored for the student management system by using two tables (students and courses) with detailed fields, referential integrity via foreign keys, and constraints such as unique email addresses. It even considers future scalability with a potential enrollments join table, showing a deep understanding of the problem\'s requirements.\"]', 100, 1, '2025-06-26 05:48:38', 1),
(6, 6, 4, '{\"Database Schema Design\":\"<p>The database is organized around a normalized, two‐table structure: a <strong>courses</strong> table and a <strong>students</strong> table. The <strong>courses</strong> table holds each course’s unique identifier, name, optional description, and automatic <code>created_at</code>/<code>updated_at</code> timestamps; the <strong>students</strong> table stores each student’s auto‐incremented ID, first and last name, a unique email address, a foreign key <code>course_id</code> linking back to the courses table, and its own timestamp fields for creation and updates. This design enforces referential integrity via the foreign key constraint—so you cannot assign a student to a non-existent course—and ensures one student per email through a unique index. If in the future you need to allow many courses per student, you can replace the <code>course_id</code> with an <strong>enrollments</strong> join table (with composite primary key on <code>student_id</code> and <code>course_id</code>). At the application level, you’d enforce required fields, appropriate string lengths, and valid email formats before inserting or updating records, while letting the database automatically track when rows are added or modified.</p>\"}', '{\"Database Schema Design\": 100}', '[\"Database Schema Design: The solution provides a detailed two-table schema (courses and students) tailored to the student management system, explicitly addressing the CRUD requirements by enforcing referential integrity through foreign keys and ensuring unique student emails, with consideration of future enhancements.\"]', 100, 2, '2025-06-26 06:22:10', 1),
(7, 6, 4, '{\"Database Schema Design\":\"<p><br></p>\"}', '{\"Database Schema Design\": 0}', '[\"Database Schema Design: The submission contains no specific details on how to design the MySQL schema for student records, including fields such as name, email, and course. There is no explanation of the tables, relationships, data types, or indexing tailored to this Student Management System problem.\"]', 0, 3, '2025-06-26 06:29:24', 1);

-- --------------------------------------------------------

--
-- Table structure for table `user`
--

CREATE TABLE `user` (
  `id` int NOT NULL,
  `username` varchar(150) NOT NULL,
  `password` varchar(200) NOT NULL,
  `role` varchar(20) NOT NULL,
  `name` varchar(200) DEFAULT NULL,
  `htno` varchar(50) DEFAULT NULL,
  `status` varchar(20) DEFAULT NULL,
  `must_change_password` tinyint(1) DEFAULT NULL,
  `password_changed_at` datetime DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  `session_token` varchar(200) DEFAULT NULL,
  `force_logout_at` datetime DEFAULT NULL,
  `last_login` datetime DEFAULT NULL,
  `current_login` datetime DEFAULT NULL,
  `login_count` int DEFAULT NULL,
  `is_online` tinyint(1) DEFAULT '0',
  `last_activity` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumping data for table `user`
--

INSERT INTO `user` (`id`, `username`, `password`, `role`, `name`, `htno`, `status`, `must_change_password`, `password_changed_at`, `created_at`, `session_token`, `force_logout_at`, `last_login`, `current_login`, `login_count`, `is_online`, `last_activity`) VALUES
(1, 'admin', 'scrypt:32768:8:1$0ToQJ9o5fTeWv0L5$43c42b9eb8cd0de370d8409563cc48b84ae870bb425682368e3df5157b67687389c78482e24472f07e6eea043934246f65be39e3a5d3606518e37e96478e6b6a', 'admin', 'Admin', '100', 'active', 0, '2025-06-19 09:52:01', NULL, '396d2e318e8e4a24422b037c7274a502444ee9e9b8ef6e5ed001c5e134fcf9c4', '2025-06-24 05:24:45', '2025-06-26 09:53:14', '2025-06-26 10:10:58', 20, 1, '2025-06-26 10:10:58'),
(2, 'teacher', 'scrypt:32768:8:1$TOfD9hrARiuayzUh$ff9c4d1aba5bff2d59475fcbcafbb3d3b6be1bb1d7d1611ed01cd8278f8cce2de738a09e1e8fc73a650b37759daa7125cca196f28890f5b91d33dbd1687ca36f', 'teacher', 'Teacher', '', 'active', 0, '2025-06-23 10:18:23', '2025-06-19 09:59:03', 'd8dfdd4889fef69819fa56eb124f55e6f6a7526bd777bd7466f66396961db8cc', '2025-06-24 05:24:45', '2025-06-25 06:29:14', '2025-06-26 08:27:56', 13, 1, '2025-06-26 08:27:56'),
(3, '12bd1a0501', 'scrypt:32768:8:1$kuLzkJJipUzAG7IA$39f2b30b2db1961f1f1754d26e822a778e2bb86703fb1d5b96a81f1262c950cce95a31ce9f4207ca4190e1272a1ea1f6afa8018d9637b89cccca9af3d4cbdf22', 'student', 'Satish', '12bd1a0501', 'active', 0, '2025-06-19 10:39:50', '2025-06-19 10:01:52', 'rlPLLY_jlFIqDGhAIl2JUZsgITuoWI-o6MfC2idk4c8', '2025-06-24 10:03:02', '2025-06-25 10:36:47', '2025-06-26 10:11:11', 7, 1, '2025-06-26 10:11:11'),
(4, 'ishaan', 'scrypt:32768:8:1$f9gOULkl04utFchj$30f86398a82b663c18082e27f8a813fda12070bedf9f998e42239a6bbfcf86ee60c021f053dc88d75a787c49b6922b75ce06ad5547a49d5f0d103bbb727c9377', 'student', NULL, NULL, 'active', 0, '2025-06-24 10:02:51', '2025-06-24 05:41:25', 'akk9em7kqFQ2EhNTwBj2P7Kc_ZDTZWBiGG1plH2Jfuc', NULL, '2025-06-24 10:06:36', '2025-06-26 10:11:24', 3, 1, '2025-06-26 10:11:24'),
(5, 'tppavan', 'scrypt:32768:8:1$ZTulRAaYAtMP0ZiR$68030dafdea00620a26a0f8ae485c273311aa878ad6c76a72fe647e8355a25750711f9ca7579e3946ba8b6125199299ef038a3e0ba89fbbdd132aca9bd1d28fd', 'teacher', 'Pavan', NULL, 'active', 0, '2025-06-24 05:46:09', '2025-06-24 05:42:05', 'nL5p0x_ZwrMbOtluQiHt6BIEc1ykI_Wnvwo0qYiGQ98', NULL, '2025-06-26 09:53:09', '2025-06-26 10:06:47', 14, 1, '2025-06-26 10:06:47'),
(6, '12bd1a0502', 'scrypt:32768:8:1$btIcKtw0CVW10xqc$16171c5f3e2b1c2f5d6231373bcc125c884fd20ac91d562826def5670a5319469de6b5bc09f92eb921c93e70b3178082a1eab508711880331755ab09e5ac2429', 'student', 'Raju', '12bd1a0502', 'active', 0, '2025-06-25 06:42:26', '2025-06-24 05:44:28', 'gwI0oqgxQaOqp3nfiDn_b1jFw7GijTlwJ385rvvbxik', '2025-06-24 10:03:02', '2025-06-25 06:42:18', '2025-06-26 06:21:46', 2, 1, '2025-06-26 06:21:46'),
(7, '12bd1a0503', 'scrypt:32768:8:1$L5rzVSbqcsgUcE4K$24d55ad77b448dd7b3b98123f3e0b3aaad9251a987916bf35e9d8230419a507c913c57183e4d1a4d56e28c6132e849fd6852afe29c220b3df0428e95447e3545', 'student', 'Ramu', '12bd1a0503', 'active', 0, '2025-06-26 05:46:57', '2025-06-24 05:44:29', 'GT7zrWwemo8tpk6c4Z-anUMYK1cc-S9m0hUJPpGWojg', '2025-06-24 10:03:02', '2025-06-26 05:46:49', '2025-06-26 09:41:22', 2, 1, '2025-06-26 09:41:22');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `course`
--
ALTER TABLE `course`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `code` (`code`),
  ADD KEY `teacher_id` (`teacher_id`);

--
-- Indexes for table `group`
--
ALTER TABLE `group`
  ADD PRIMARY KEY (`id`),
  ADD KEY `course_id` (`course_id`);

--
-- Indexes for table `problem`
--
ALTER TABLE `problem`
  ADD PRIMARY KEY (`id`),
  ADD KEY `course_id` (`course_id`),
  ADD KEY `created_by` (`created_by`);

--
-- Indexes for table `student_group`
--
ALTER TABLE `student_group`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_student_group` (`student_id`,`group_id`),
  ADD KEY `group_id` (`group_id`);

--
-- Indexes for table `submission`
--
ALTER TABLE `submission`
  ADD PRIMARY KEY (`id`),
  ADD KEY `problem_id` (`problem_id`),
  ADD KEY `ix_submission_user_problem` (`student_id`,`problem_id`),
  ADD KEY `ix_submission_created_at` (`created_at`);

--
-- Indexes for table `user`
--
ALTER TABLE `user`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `course`
--
ALTER TABLE `course`
  MODIFY `id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `group`
--
ALTER TABLE `group`
  MODIFY `id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `problem`
--
ALTER TABLE `problem`
  MODIFY `id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=11;

--
-- AUTO_INCREMENT for table `student_group`
--
ALTER TABLE `student_group`
  MODIFY `id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT for table `submission`
--
ALTER TABLE `submission`
  MODIFY `id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=9;

--
-- AUTO_INCREMENT for table `user`
--
ALTER TABLE `user`
  MODIFY `id` int NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=8;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `course`
--
ALTER TABLE `course`
  ADD CONSTRAINT `course_ibfk_1` FOREIGN KEY (`teacher_id`) REFERENCES `user` (`id`);

--
-- Constraints for table `group`
--
ALTER TABLE `group`
  ADD CONSTRAINT `group_ibfk_1` FOREIGN KEY (`course_id`) REFERENCES `course` (`id`);

--
-- Constraints for table `problem`
--
ALTER TABLE `problem`
  ADD CONSTRAINT `problem_ibfk_1` FOREIGN KEY (`course_id`) REFERENCES `course` (`id`),
  ADD CONSTRAINT `problem_ibfk_2` FOREIGN KEY (`created_by`) REFERENCES `user` (`id`);

--
-- Constraints for table `student_group`
--
ALTER TABLE `student_group`
  ADD CONSTRAINT `student_group_ibfk_1` FOREIGN KEY (`student_id`) REFERENCES `user` (`id`),
  ADD CONSTRAINT `student_group_ibfk_2` FOREIGN KEY (`group_id`) REFERENCES `group` (`id`);

--
-- Constraints for table `submission`
--
ALTER TABLE `submission`
  ADD CONSTRAINT `submission_ibfk_1` FOREIGN KEY (`student_id`) REFERENCES `user` (`id`),
  ADD CONSTRAINT `submission_ibfk_2` FOREIGN KEY (`problem_id`) REFERENCES `problem` (`id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
