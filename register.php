<?php require 'db.php'; $msg='';
if($_SERVER['REQUEST_METHOD']==='POST'){
  $u=clean($_POST['username'],30); $p=$_POST['password'];
  if(!preg_match('/^[A-Za-z0-9_]{3,30}$/',$u)){
    $msg='Username must be 3-30 characters: letters, numbers, underscore only.';   // whitelist validation
  } elseif($errs=password_errors($p)){
    $msg='Password must contain '.implode(', ',$errs).'.';                          // password policy
  } else {
    try{
      $s=$db->prepare("INSERT INTO users(username,password) VALUES(?,?)");
      $s->execute([$u,password_hash($p,PASSWORD_DEFAULT)]);
      header('Location: login.php?registered=1'); exit;
    }catch(Exception $e){ $msg='Username already taken.'; }
  }
}?>
<!DOCTYPE html><html><head><title>Register</title><link rel="stylesheet" href="style.css"></head><body>
<div class="nav"><b>Attendance System</b><span><a href="login.php">Login</a></span></div>
<div class="wrap"><div class="card"><h2>Register</h2>
<?php if($msg) echo "<div class='err'>".e($msg)."</div>"; ?>
<form method="post">Username<input name="username" required maxlength="30" pattern="[A-Za-z0-9_]{3,30}">
Password<input type="password" name="password" required minlength="8">
<div class="hint">Min. 8 characters with uppercase, lowercase and a number.</div><br>
<button>Register</button></form></div></div></body></html>
