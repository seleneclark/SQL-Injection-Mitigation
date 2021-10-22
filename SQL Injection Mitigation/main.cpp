//
//  main.cpp
//  SQL Injection Mitigation
//
//  Created by Selene on 10/21/21.
//

#include <iostream>
using namespace std;


void display(string testString){
   cout << testString + "\n\n";
}
string genQuery(string username, string password){
   string authenticate = "SELECT authenticate FROM passwordList WHERE name='" + username + "' and passwd='" + password + "';";
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
   
   cout << "Valid Input: \n\n";
   
   for (int i = 0; i < 5; i++){
	  string testString = genQuery(validTestCases[i][0], validTestCases[i][1]);
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
   
   cout << "Tautology Attack: \n\n";
   
   for (int i = 0; i < 5; i++){
	  string testString = genQuery(tautologyVulnerabilities[i][0], tautologyVulnerabilities[i][1]);
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
   
   cout << "Tautology Attack: \n\n";
   
   for (int i = 0; i < 5; i++){
	  string testString = genQuery(unionVulnerabilities[i][0], unionVulnerabilities[i][1]);
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
   
   cout << "Additional Statement Attack: \n\n";
   
   for (int i = 0; i < 5; i++){
	  string testString = genQuery(addStateVulnerabilities[i][0], addStateVulnerabilities[i][1]);
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
   
   cout << "Comment Attack: \n\n";
   
   for (int i = 0; i < 5; i++){
	  string testString = genQuery(testCommentVulnerabilities[i][0], testCommentVulnerabilities[i][1]);
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
