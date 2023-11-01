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
 * Copyright 2014 Yusuke Kawamoto
 */
package bham.leakiest.comparator;

import java.util.*;

/**
 * This class provides a comparator used for sotring pairs.
 *
 * @author Yusuke Kawamoto
 * @version 1.3
 */
public class ComparatorStringWithInt implements Comparator<Pair<String,Integer>> {
	/**
	 * Constructs a comparator.
	 */
	public ComparatorStringWithInt() {}

	/**
	 * Comparator for two strings with sort indexes.
	 * 
	 * @param swsi1 a string with a sort index
	 * @param swsi2 a string with a sort index
	 * @return integer that represents the result of comparing the two strings with sort indexes. 
	 */
	public int compare(Pair<String,Integer> swsi1, Pair<String,Integer> swsi2) {
    	try {
    		double d1 = Double.parseDouble(swsi1.getElement1()); 
    		double d2 = Double.parseDouble(swsi2.getElement1()); 
    		if(d1 > d2)
    			return 1;
    		else if (d1 == d2)
    			return 0;
    		else
    			return -1;
    	} catch(Exception e) {
	    	return swsi1.getElement1().compareTo(swsi2.getElement1());
    	}
    }
}
