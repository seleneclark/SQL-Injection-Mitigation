
#include <iostream>
#include <string>
using namespace std;



std::string SingleString (std::string user, std::string pass);
std::string ToStrongSql (std::string user, std::string pass);
std::string FilterToStrong (std::string str);
std::string FilterToWeak (std::string str);
std::string ToRemove (std::string str, std::string word);

//Prompt the user for their username
string getUsername()
{
    string username;
    cout << "Please enter your username: ";
    getline (cin, username);
    return username;
}

//Prompt the user for their password
string getPassword()
{
    string password;
    cout << "Please enter your password: ";
    getline (cin, password);
    return password;
}

//takes the username and password and makes a single string.
string SingleString (string user, string pass)
{
  string sql = "select username from users where username= \'"
    + user + "\' AND password = \'" + pass + "\'";

  return sql;
}

//Filter the input and return sql
string ToStrongSql (std::string user, std::string pass)
{
  string sql = "";
  user = FilterToStrong (user);
  pass = FilterToStrong (pass);
  sql = SingleString (user, pass);
  return sql;
}

//here we deletes characters different
string FilterToStrong (string str)
{
  string filteredStr = "";
  for (int i = 0; i < str.length (); i++)
    {
      char ch = str[i];
      if ((
	    //Characters must be to z, A to Z, 0 to 9
	    (ch <= 'Z' && ch >= 'A') ||
	    (ch <= 'z' && ch >= 'a') ||
	    (isdigit (ch)) ||
	    ch == '#' || ch == '!' || ch == '$' || ch == '?' || ch == '*'))
	{
	  filteredStr += ch;
	}
    }
  return filteredStr;
}


//delete space here
string ToRemove (string str, string word)
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


//check words that can put the system at risk, the user can take advantage and create two sql statements with these words.
string FilterToWeak (string str)
{
  //You cannot use those words.
  string filteredStr = "";

  str = ToRemove (str, " union ");
  str = ToRemove (str, " and ");
  str = ToRemove (str, " or ");


  str = ToRemove (str, " UNION ");
  str = ToRemove (str, " AND ");
  str = ToRemove (str, " OR ");




  //Deleting ; space and -
  for (int i = 0; i < str.length (); i++)
    {
      char ch = str[i];
      if (ch != ';' && ch != ' ' && ch != '-')
	{
	  filteredStr += ch;
	}
    }

  return filteredStr;
}

//Here is the main program, it interacts with the user and joins the strings
int main ()
{
  string username, password, sql, SqlStrong, SqlWeak;

  username = getUsername();
  password = getPassword();

  //To show SQL INJECTION MITIGATION efficiencies
  sql = SingleString (username, password);
  cout << "Vulnerable: " << sql << endl;
  SqlStrong = ToStrongSql (username, password);
  cout << "Strong: " << SqlStrong << endl;

  return 0;
}



