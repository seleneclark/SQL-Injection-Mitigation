//
//  main.cpp
//  SQL Injection Mitigation
//
//  Created by Selene on 10/21/21.
//

#include <iostream>
#include <string>
using namespace std;


void display(string testString){
   cout << testString + "\n";
}
string genQuery(string username, string password){
   string authenticate = "SELECT authenticate FROM passwordList WHERE name='" + username + "' and passwd='" + password + "';";
   return authenticate;
}

//delete space here
string toRemove(string str, string word)
{

  if (str.find (word) != string::npos)
	{
	  size_t p = -1;

	  string tempWord = word + " ";
	  while ((p = str.find (word)) != string::npos)
	str.replace (p, tempWord.length (), "");

	  tempWord = " " + word;
	  while ((p = str.find (word)) != string::npos)
	str.replace (p, tempWord.length (), "");
	}

  return str;
}

string genQueryWeak(string str)
{
  //You cannot use those words.
  string filteredStr = "";

  str = toRemove(str, " union ");
  str = toRemove(str, " and ");
  str = toRemove(str, " or ");


  str = toRemove(str, " UNION ");
  str = toRemove(str, " AND ");
  str = toRemove(str, " OR ");


  //Deleting ; space and -
  for (int i = 0; i < str.length (); i++){
   char ch = str[i];
   if (ch != ';' && ch != ' ' && ch != '-'){
	filteredStr += ch;
   }
  }
  return filteredStr;
}

string verifyUsername(string username){
   string usernameList[] = {"name", "123456789", "aVeryVeryVeryVeryVeryVeryVeryVeryLongUsername","__User__Name__", "name__123456789"};
   string verifiedUsername = "";
   for (int i = 0; i < 5; i++){
	  if (usernameList[i] == username){
		 verifiedUsername = username;
	  }
   }
   return verifiedUsername;
}

string verifyPassword(string password){
   string passwordList[] = {"password", "123456789", "aSecurePasswordIsALongPasswordSoLetsMakeItLong","__Password__", "987654321_anotherPassword"};
   string verifiedPassword = "";
   for (int i = 0; i < 5; i++){
	  if (passwordList[i] == password){
		 verifiedPassword = password;
	  }
   }
   return verifiedPassword;
}

string genQueryStrong(string username, string password){
   
   string verifiedUsername = verifyUsername(username);
   string verifiedPassword = verifyPassword(password);
   
   string authenticate = "SELECT authenticate FROM passwordList WHERE name='" + verifiedUsername + "' and passwd='" + verifiedPassword + "';";
   return authenticate;
}

void testValid(){
   string validTestCases[5][2];
   validTestCases[0][0] = "name";
   validTestCases[1][0] = "123456789";
   validTestCases[2][0] = "aVeryVeryVeryVeryVeryVeryVeryVeryLongUsername";
   validTestCases[3][0] = "__User__Name__";
   validTestCases[4][0] = "name__123456789";

   validTestCases[0][1] = "password";
   validTestCases[1][1] = "123456789";
   validTestCases[2][1] = "aSecurePasswordIsALongPasswordSoLetsMakeItLong";
   validTestCases[3][1] = "__Password__";
   validTestCases[4][1] = "987654321_anotherPassword";
   
   string testString;
   cout << "\nValid Input: \n\n";
   for (int i = 0; i < 5; i++){
	  testString = genQuery(validTestCases[i][0], validTestCases[i][1]);
	  display(testString);
   }
   
   cout << "\nWeak Mitigation - Valid Input: \n\n";
   for (int i = 0; i < 5; i++){
	  testString = genQuery(genQueryWeak(validTestCases[i][0]), genQueryWeak(validTestCases[i][1]));
	  display(testString);
   }
   
   cout << "\nStrong Mitigation - Valid Input: \n\n";
   for (int i = 0; i < 5; i++){
	  testString = genQueryStrong(validTestCases[i][0], validTestCases[i][1]);
	  display(testString);
   }
}

void testTautology(){
   string tautologyVulnerabilities[5][2];
   tautologyVulnerabilities[0][0] = "name";
   tautologyVulnerabilities[1][0] = "123456789";
   tautologyVulnerabilities[2][0] = "aVeryVeryVeryVeryVeryVeryVeryVeryLongUsername";
   tautologyVulnerabilities[3][0] = "__User__Name__";
   tautologyVulnerabilities[4][0] = "name__123456789";
   
   tautologyVulnerabilities[0][1] = "password' OR 'x'='x";
   tautologyVulnerabilities[1][1] = "123456789' OR 'x'='x";
   tautologyVulnerabilities[2][1] = "aSecurePasswordIsALongPasswordSoLetsMakeItLong' OR 'x'='x";
   tautologyVulnerabilities[3][1] = "__Password__' OR 'x'='x";
   tautologyVulnerabilities[4][1] = "987654321_anotherPassword' OR 'x'='x";
   
   string testString;
   cout << "\nTautology Attack: \n\n";
   for (int i = 0; i < 5; i++){
	  testString = genQuery(tautologyVulnerabilities[i][0], tautologyVulnerabilities[i][1]);
	  display(testString);
   }
   
   cout << "\nWeak Mitigation - Tautology Attack: \n\n";
   for (int i = 0; i < 5; i++){
	  testString = genQuery(genQueryWeak(tautologyVulnerabilities[i][0]), genQueryWeak(tautologyVulnerabilities[i][1]));
	  display(testString);
   }
   
   cout << "\nStrong Mitigation - Tautology Attack: \n\n";
   for (int i = 0; i < 5; i++){
	  testString = genQueryStrong(tautologyVulnerabilities[i][0], tautologyVulnerabilities[i][1]);
	  display(testString);
   }
}

void testUnion(){
   string unionVulnerabilities[5][2];
   unionVulnerabilities[0][0] = "name";
   unionVulnerabilities[1][0] = "123456789";
   unionVulnerabilities[2][0] = "aVeryVeryVeryVeryVeryVeryVeryVeryLongUsername";
   unionVulnerabilities[3][0] = "__User__Name__";
   unionVulnerabilities[4][0] = "name__123456789";
   
   unionVulnerabilities[0][1] = "password' UNION SELECT authenticate FROM passwordList";
   unionVulnerabilities[1][1] = "123456789' UNION SELECT authenticate FROM passwordList";
   unionVulnerabilities[2][1] = "aSecurePasswordIsALongPasswordSoLetsMakeItLong' UNION SELECT authenticate FROM passwordList";
   unionVulnerabilities[3][1] = "__Password__' UNION SELECT authenticate FROM passwordList";
   unionVulnerabilities[4][1] = "987654321_anotherPassword' UNION SELECT authenticate FROM passwordList";
   
   string testString;
   cout << "\nUnion Attack: \n\n";
   for (int i = 0; i < 5; i++){
	  string testString = genQuery(unionVulnerabilities[i][0], unionVulnerabilities[i][1]);
	  display(testString);
   }
   
   cout << "\nWeak Mitigation - Union Attack: \n\n";
   for (int i = 0; i < 5; i++){
	  testString = genQuery(genQueryWeak(unionVulnerabilities[i][0]), genQueryWeak(unionVulnerabilities[i][1]));
	  display(testString);
   }
   
   cout << "\nStrong Mitigation - Union Attack: \n\n";
   for (int i = 0; i < 5; i++){
	  testString = genQueryStrong(unionVulnerabilities[i][0], unionVulnerabilities[i][1]);
	  display(testString);
   }
}

void testAddState(){
   string addStateVulnerabilities[5][2];
   addStateVulnerabilities[0][0] = "name";
   addStateVulnerabilities[1][0] = "123456789";
   addStateVulnerabilities[2][0] = "aVeryVeryVeryVeryVeryVeryVeryVeryLongUsername";
   addStateVulnerabilities[3][0] = "__User__Name__";
   addStateVulnerabilities[4][0] = "name__123456789";
   
   addStateVulnerabilities[0][1] = "password'; INSERT INTO passwordList (name, passwd) VALUES 'Bob', '1234";
   addStateVulnerabilities[1][1] = "123456789'; INSERT INTO passwordList (name, passwd) VALUES 'Bob', '1234";
   addStateVulnerabilities[2][1] = "aSecurePasswordIsALongPasswordSoLetsMakeItLong'; INSERT INTO passwordList (name, passwd) VALUES 'Bob', '1234";
   addStateVulnerabilities[3][1] = "__Password__'; INSERT INTO passwordList (name, passwd) VALUES 'Bob', '1234";
   addStateVulnerabilities[4][1] = "987654321_anotherPassword'; INSERT INTO passwordList (name, passwd) VALUES 'Bob', '1234";
   
   string testString;
   cout << "\nAdditional Statement Attack: \n\n";
   for (int i = 0; i < 5; i++){
	  testString = genQuery(addStateVulnerabilities[i][0], addStateVulnerabilities[i][1]);
	  display(testString);
   }
   
   cout << "\nWeak Mitigation - Additional Statement Attack: \n\n";
   for (int i = 0; i < 5; i++){
	  testString = genQuery(genQueryWeak(addStateVulnerabilities[i][0]), genQueryWeak(addStateVulnerabilities[i][1]));
	  display(testString);
   }
   
   cout << "\nStrong Mitigation - Additional Statement Attack: \n\n";
   for (int i = 0; i < 5; i++){
	  testString = genQueryStrong(addStateVulnerabilities[i][0], addStateVulnerabilities[i][1]);
	  display(testString);
   }
}

void testComment(){
   string testCommentVulnerabilities[5][2];
   testCommentVulnerabilities[0][0] = "Root'; --";
   testCommentVulnerabilities[1][0] = "Root'; --";
   testCommentVulnerabilities[2][0] = "Root'; --";
   testCommentVulnerabilities[3][0] = "Root'; --";
   testCommentVulnerabilities[4][0] = "Root'; --";
   
   testCommentVulnerabilities[0][1] = "password";
   testCommentVulnerabilities[1][1] = "123456789";
   testCommentVulnerabilities[2][1] = "aSecurePasswordIsALongPasswordSoLetsMakeItLong";
   testCommentVulnerabilities[3][1] = "__Password__";
   testCommentVulnerabilities[4][1] = "987654321_anotherPassword";
   
   string testString;
   cout << "\nComment Attack: \n\n";
   for (int i = 0; i < 5; i++){
	  testString = genQuery(testCommentVulnerabilities[i][0], testCommentVulnerabilities[i][1]);
	  display(testString);
   }
   
   cout << "\nWeak Mitigation - Comment Attack: \n\n";
   for (int i = 0; i < 5; i++){
	  testString = genQuery(genQueryWeak(testCommentVulnerabilities[i][0]), genQueryWeak(testCommentVulnerabilities[i][1]));
	  display(testString);
   }
   cout << "\nStrong Mitigation - Comment Attack: \n\n";
   for (int i = 0; i < 5; i++){
	  testString = genQueryStrong(testCommentVulnerabilities[i][0], testCommentVulnerabilities[i][1]);
	  display(testString);
   }
}

int main(int argc, const char * argv[]) {
   testValid();
   testTautology();
   testUnion();
   testAddState();
   testComment();
   
   return 0;
}
