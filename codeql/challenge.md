### 1.Find the thief

```
import cpp
import tutorial

from Person culprit
where culprit.getHeight()>150 and
    not (culprit.getHairColor()="blond") and
    culprit.getAge()>30 and
    culprit.getLocation()="east" and
    (culprit.getHairColor()="black" or culprit.getHairColor()="brown") and
    (culprit.getHeight()<=180 or culprit.getHeight()>=190) and
    culprit.getAge() < max(int i | exists(Person others | others.getAge()=i) | i) and
	culprit.getHeight() < max(int i | exists(Person others | others.getHeight()=i) | i) and
	culprit.getHeight() < avg(int i | exists(Person others | others.getHeight()=i) | i) and
	culprit.getAge() = max(int i | exists(Person others | (others.getAge()=i and others.getLocation()="east")) | i)
select culprit

//Hester
```

### 2.Catch the fire starter

```
import cpp
import tutorial

predicate is_south(Person p)
{
   	 p.getLocation()="south"
}

predicate is_bald(Person p)
{
    not exists(string s|p.getHairColor()=s)
}

class Southerner extends Person
{
  Southerner()
  {
   	 is_south(this)
  }
}

class Child extends Person
{
	Child()
  {
  		this.getAge()<10 
  }
  override predicate isAllowedIn(string region)
  {
   		 region=this.getLocation()
  }
}

from Southerner s
where s.isAllowedIn("north") and is_bald(s)
select s

//Charlie
//Hugh
```

### 3.Crown the rightful heir

```
import cpp
import tutorial

Person relativeOf(Person p)
{
  	parentOf*(p)=parentOf*(result)
}

predicate hasCriminalRecord(Person p)
{
	p in ["Hester","Charlie","Hugh"]
}

from Person p
where p=any(Person p2 |  p2="King Basil" | relativeOf(p2)) and
not p.isDeceased() and
not p="King Basil" and
not hasCriminalRecord(p)
select p

//Clara
```

### 4.Cross the river

```
class Cargo extends string {
  Cargo() {
    this = "Nothing" or
    this = "Goat" or
    this = "Cabbage" or
    this = "Wolf"
  }
}

/** One of two shores. */
class Shore extends string {
  Shore() {
    this = "Left" or
    this = "Right"
  }

  /** Returns the other shore. */
  Shore other() {
    this = "Left" and result = "Right"
    or
    this = "Right" and result = "Left"
  }
}

/** Renders the state as a string. */
string renderState(Shore manShore, Shore goatShore, Shore cabbageShore, Shore wolfShore) {
  result = manShore + "," + goatShore + "," + cabbageShore + "," + wolfShore
}

/** A record of where everything is. */
class State extends string {
  Shore manShore;
  Shore goatShore;
  Shore cabbageShore;
  Shore wolfShore;

  State() { this = renderState(manShore, goatShore, cabbageShore, wolfShore) }
   State ferry(Cargo cargo) {
    cargo = "Nothing" and
    result = renderState(manShore.other(), goatShore, cabbageShore, wolfShore)
    or
    cargo = "Goat" and
    result = renderState(manShore.other(), goatShore.other(), cabbageShore, wolfShore)
    or
    cargo = "Cabbage" and
    result = renderState(manShore.other(), goatShore, cabbageShore.other(), wolfShore)
    or
    cargo = "Wolf" and
    result = renderState(manShore.other(), goatShore, cabbageShore, wolfShore.other())
  }
  
  predicate isSafe()
{
    // The goat can't eat the cabbage.
    (goatShore != cabbageShore or goatShore = manShore) and
    // The wolf can't eat the goat.
    (wolfShore != goatShore or wolfShore = manShore)
}
  
  State safeFerry(Cargo cargo) { result = this.ferry(cargo) and result.isSafe() }
  
  State reachesVia(string path,string state_reached)
	{
     	result=this and
      	path="" and
      	state_reached="" or
      	exists(string state_reached_sofar,Cargo cargo,string new_path | state_reached=state_reached_sofar+"/"+result and
        state_reached_sofar.indexOf(result) and
      	result=this.reachesVia(new_path,state_reached_sofar).safeFerry(cargo) and
      	new_path+"ferry "+cargo+"\n"=path)
	}
}

/** The initial state, where everything is on the left shore. */
class InitialState extends State {
  InitialState() { this = renderState("Left", "Left", "Left", "Left") }
}

/** The goal state, where everything is on the right shore. */
class GoalState extends State {
  GoalState() { this = renderState("Right", "Right", "Right", "Right") }
}

from string path
where any(InitialState i).reachesVia(path,_)=any(GoalState end)
select path
```