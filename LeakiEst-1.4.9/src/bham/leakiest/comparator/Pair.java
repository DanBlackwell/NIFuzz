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

/**
 * This class constructs and manipulates a pair.
 * It is used to sort a channel matrix and probability distribution.
 * 
 * @author Yusuke Kawamoto
 * @version 1.3
 */
public class Pair<T1, T2> {
	private T1 element1;
	private T2 element2;

	public Pair() {}

	public Pair(T1 element1, T2 element2) {
		this.element1 = element1;
		this.element2 = element2;
	}
	
	
	/**
	 * Sets elements of the pair.
	 * 
	 * @param element1 the first element of the pair
	 * @param element2 the second element of the pair
	 */
	public void setElements(T1 element1, T2 element2) {
		this.element1 = element1;
		this.element2 = element2;
	}

	/**
	 * Sets the first element of the pair.
	 * 
	 * @param element1 the first element of the pair
	 */
	public void setElement1(T1 element1) {
		this.element1 = element1;
	}

	/**
	 * Sets the second element of the pair.
	 * 
	 * @param element2 the second element of the pair
	 */
	public void setElement2(T2 element2) {
		this.element2 = element2;
	}

	/**
	 * Returns the first element of the pair.
	 * 
	 * @return the first element of the pair
	 */
	public T1 getElement1() {
		return this.element1;
	}

	/**
	 * Returns the second element of the pair.
	 * 
	 * @return the second element of the pair
	 */
	public T2 getElement2() {
		return this.element2;
	}
}
