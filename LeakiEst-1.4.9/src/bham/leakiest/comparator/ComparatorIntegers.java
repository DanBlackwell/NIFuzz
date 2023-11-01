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
public class ComparatorIntegers implements Comparator<Pair<Integer,Integer>> {
	/**
	 * Constructs a comparator.
	 */
	public ComparatorIntegers() {}

	/**
	 * Comparator for two pairs whose values are integer.
	 * 
	 * @param pair1 a pair consisting of an integer and a sort index
	 * @param pair2 a pair consisting of an integer and a sort index
	 * @return integer that represents the result of comparing the two integers with sort indexes. 
	 */
	public int compare(Pair<Integer,Integer> pair1, Pair<Integer,Integer> pair2) {
		if(pair1.getElement1() > pair2.getElement1())
			return 1;
		else if(pair1.getElement1() < pair2.getElement1())
			return -1;
		else if(pair1.getElement2() > pair2.getElement2())
			return 1;
		else if(pair1.getElement2() < pair2.getElement2())
			return -1;
		else
			return 0;
    }
}
