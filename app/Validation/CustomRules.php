<?php
namespace App\Validation;

class CustomRules{

  // Rule is to validate mobile number digits
  public function mobileValidation($mobile){
    /*Checking: Number must start from 5-9{Rest Numbers}*/
    if(preg_match( '/^[5-9]{1}[0-9]+/', $mobile)){
      
      /*Checking: Mobile number must be of 9 digits*/
      $bool = preg_match('/^[0-9]{9}+$/', $mobile);
      return $bool == 0 ? false : true; 
      
    }else{
      return false;
    }
  }

  public function ageValidation($age){
    if($age>=18) return true;
    else return false; 
  }
}