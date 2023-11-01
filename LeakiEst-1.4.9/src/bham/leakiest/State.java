/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2013 Tom Chothia, Yusuke Kawamoto and Chris Novakovic
 */
package bham.leakiest;

import java.util.*;

/**
 * This class represents a state.
 * 
 * @author Tom Chothia
 * @author Yusuke Kawamoto
 * @author Chris Novakovic
 * @version 1.2
 */
public class State {
	private Map<String, String> map = new TreeMap<String, String>();
    private int verbose = 3;

	/**
	 * Constructs the empty state.
	 */
	public State() {
		if(verbose >= 5)
			System.out.println(" A state is created.");
	}

	/**
	 * Constructs a state with the initial values.
	 * 
	 * @param str label (e.g. variable)
	 */
	public State(String str) {
		this.map.put(str, "input");
		if(verbose >= 5)
			System.out.println(" A state is created.");
	}

	/**
	 * Constructs a state with the initial values.
	 * 
	 * @param str label (e.g. variable)
	 * @param vals value
	 */
	public State(String[] str, String[] vals) {
		if(str.length == vals.length) {
			for(int i = 0; i < str.length; i++) {
				this.map.put(str[i], vals[i]);
			}
			if(verbose >= 5)
				System.out.println(" A state is created.");
		}
	}

	/**
	 * Returns the number of all variables in the state.
	 * 	
	 * @return the number of all variables in the state
	 */
	public int getStatesNum() {
		Iterator it = this.map.keySet().iterator();
		int counter = 0;
		while (it.hasNext()) {
            counter++;
            it.next();
		}
		return counter;
	}
	
	/**
	 * Returns the list of all variable in the state.
	 * 
	 * @return array of strings representing variables
	 */
	public String[] getVars() {
		String[] vars = new String[this.getStatesNum()];
		Iterator<Map.Entry<String,String>> it = this.map.entrySet().iterator();
		int index = 0;
		while (it.hasNext()) {
			Map.Entry<String,String> itnext = it.next(); 
			vars[index] = itnext.getKey();
			index++;
		}
		return vars;
	}

	/**
	 * Returns the value of the variable in the state.
	 * 
	 * @param var variable
	 * @return value of the variable
	 */
	public String getValue(String var) {
		return this.map.get(var);
	}

	/**
	 * Updates the value of the variable in the state.
	 * @param var variable
	 * @param val the value of the variable
	 */
	public void updateValue(String var, String val) {
		this.map.put(var, val);
		if(verbose >= 5)
			System.out.println(" Added [" + var + "=" + val + "]");
	}

	/**
	 * Remove the variable from the state.
	 * @param var variable
	 */
	public void removeValue(String var) {
		if(verbose >= 5)
			System.out.println(" Removed [" + var + "=" + this.map.get(var) + "]");
		this.map.remove(var);
	}

	/**
	 * Checks whether the two state are equivalent, 
	 * 
	 * @param st state
	 * @return whether this and st are equivalent states.
	 */
	public boolean isEqual(State st) {
		if(this.map.size() == st.map.size()) {
			boolean equiv = true;
			Iterator<Map.Entry<String,String>> it0 = this.map.entrySet().iterator();
			Iterator<Map.Entry<String,String>> it1 = st.map.entrySet().iterator();
			while (it0.hasNext() && it1.hasNext()) {
				Map.Entry<String,String> it0next = it0.next(); 
				Map.Entry<String,String> it1next = it1.next(); 
				if(it0next.getKey() != it1next.getKey() ||
				   it0next.getValue() != it1next.getValue()) {
					//System.out.println("is Equal returns true.");
					equiv = false;
				}
			}
			return equiv;
		} else {
			return false;
		}
		//String.format("%s", map.entrySet());
	}

	/**
	 * Returns the name of the variable.
	 * 
	 * @param var variable
	 * @return the name of the variable
	 */
	public String stringValue(String var) {
		return String.format("{ %s = %d }", var, getValue(var));
	}

	/**
	 * Returns the string of the state.
	 * 
	 * @return the string of the state
	 */
	public String stringState() {
		return String.format("%s", map.entrySet());
	}

	/**
	 * Returns the whole state as string.
	 * @param var variable
	 * @return the whole state as string
	 */
	public String strAll(String var) {
		//for(String s : )
		if(verbose >= 5)
			System.out.println(" entry: " + map.entrySet());
		return String.format("{ %s = %d }", var, getValue(var));
	}

	/**
	 * Print the state.
	 */
	public void printState() {
		System.out.println(" State: " + map.entrySet());
	}

	/**
	 * Print the state.
	 */
	public void printState2() {
		Iterator it = this.map.keySet().iterator();
		while (it.hasNext()) {
            System.out.println(it.next());
		}
		System.out.println(" State: " + map.entrySet());
	}
}
