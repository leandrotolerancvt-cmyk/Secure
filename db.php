<?php
// ---- XSS DEFENSE #1: Security headers 
header("Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");

// ---- XSS DEFENSE #2: HttpOnly session cookie 
session_set_cookie_params(['httponly'=>true,'samesite'=>'Strict']);
session_start();

$dbname = 'attendance_secure';
$db = new PDO('mysql:host=127.0.0.1;charset=utf8mb4', 'root', '');   // XAMPP default: user root, no password
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$db->exec("CREATE DATABASE IF NOT EXISTS `$dbname` CHARACTER SET utf8mb4");
$db->exec("USE `$dbname`");
$db->exec("CREATE TABLE IF NOT EXISTS users(id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(50) UNIQUE, password VARCHAR(255))");
$db->exec("CREATE TABLE IF NOT EXISTS logs(id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(50), action VARCHAR(30), remarks TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");

// XSS DEFENSE #3: Output-escaping helper 
function e($v){ return htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }

// XSS DEFENSE #4: Input sanitizer 
function clean($v,$max=100){ return mb_substr(trim(strip_tags((string)$v)),0,$max); }

// Password policy: min 8 chars, uppercase, lowercase, number 
function password_errors($p){
  $errs=[];
  if(strlen($p)<8)              $errs[]='at least 8 characters';
  if(!preg_match('/[A-Z]/',$p)) $errs[]='at least one UPPERCASE letter';
  if(!preg_match('/[a-z]/',$p)) $errs[]='at least one lowercase letter';
  if(!preg_match('/[0-9]/',$p)) $errs[]='at least one number';
  return $errs;
}
function log_action($db,$u,$a,$r=''){ $s=$db->prepare("INSERT INTO logs(username,action,remarks) VALUES(?,?,?)"); $s->execute([$u,$a,$r]); }
