/* GLIB - Library of useful routines for C programming
 * Copyright (C) 1995-1997  Peter Mattis, Spencer Kimball and Josh MacDonald
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

/*
 * Modified by the GLib Team and others 1997-2000.  See the AUTHORS
 * file for a list of people on the GLib Team.  See the ChangeLog
 * files for a list of changes.  These files are distributed with
 * GLib at ftp://ftp.gtk.org/pub/gtk/. 
 */

/* 
 * MT safe
 */

#include "gumlist.h"
#include "gummemory.h"

#define _gum_list_alloc()         gum_malloc  (sizeof (GumList))
#define _gum_list_alloc0()        gum_malloc0 (sizeof (GumList))
#define _gum_list_free1(list)     gum_free    (list)

GumList*
gum_list_alloc (void)
{
  return _gum_list_alloc0 ();
}

/**
 * gum_list_free: 
 * @list: a #GumList
 *
 * Frees all of the memory used by a #GumList.
 * The freed elements are returned to the slice allocator.
 *
 * <note><para>
 * If list elements contain dynamically-allocated memory, 
 * they should be freed first.
 * </para></note>
 */
void
gum_list_free (GumList *list)
{
  GumList * walk;

  for (walk = list; walk != NULL;)
  {
    GumList * next;

    next = walk->next;
    gum_free (walk);
    walk = next;
  }
}

/**
 * gum_list_free_1:
 * @list: a #GumList element
 *
 * Frees one #GumList element.
 * It is usually used after gum_list_remove_link().
 */
void
gum_list_free_1 (GumList *list)
{
  _gum_list_free1 (list);
}

/**
 * gum_list_append:
 * @list: a pointer to a #GumList
 * @data: the data for the new element
 *
 * Adds a new element on to the end of the list.
 *
 * <note><para>
 * The return value is the new start of the list, which 
 * may have changed, so make sure you store the new value.
 * </para></note>
 *
 * <note><para>
 * Note that gum_list_append() has to traverse the entire list 
 * to find the end, which is inefficient when adding multiple 
 * elements. A common idiom to avoid the inefficiency is to prepend 
 * the elements and reverse the list when all elements have been added.
 * </para></note>
 *
 * |[
 * /&ast; Notice that these are initialized to the empty list. &ast;/
 * GumList *list = NULL, *number_list = NULL;
 *
 * /&ast; This is a list of strings. &ast;/
 * list = gum_list_append (list, "first");
 * list = gum_list_append (list, "second");
 * 
 * /&ast; This is a list of integers. &ast;/
 * number_list = gum_list_append (number_list, GINT_TO_POINTER (27));
 * number_list = gum_list_append (number_list, GINT_TO_POINTER (14));
 * ]|
 *
 * Returns: the new start of the #GumList
 */
GumList*
gum_list_append (GumList	*list,
	       gpointer	 data)
{
  GumList *new_list;
  GumList *last;
  
  new_list = _gum_list_alloc ();
  new_list->data = data;
  new_list->next = NULL;
  
  if (list)
    {
      last = gum_list_last (list);
      /* g_assert (last != NULL); */
      last->next = new_list;
      new_list->prev = last;

      return list;
    }
  else
    {
      new_list->prev = NULL;
      return new_list;
    }
}

/**
 * gum_list_prepend:
 * @list: a pointer to a #GumList
 * @data: the data for the new element
 *
 * Adds a new element on to the start of the list.
 *
 * <note><para>
 * The return value is the new start of the list, which 
 * may have changed, so make sure you store the new value.
 * </para></note>
 *
 * |[ 
 * /&ast; Notice that it is initialized to the empty list. &ast;/
 * GumList *list = NULL;
 * list = gum_list_prepend (list, "last");
 * list = gum_list_prepend (list, "first");
 * ]|
 *
 * Returns: the new start of the #GumList
 */
GumList*
gum_list_prepend (GumList	 *list,
		gpointer  data)
{
  GumList *new_list;
  
  new_list = _gum_list_alloc ();
  new_list->data = data;
  new_list->next = list;
  
  if (list)
    {
      new_list->prev = list->prev;
      if (list->prev)
	list->prev->next = new_list;
      list->prev = new_list;
    }
  else
    new_list->prev = NULL;
  
  return new_list;
}

/**
 * gum_list_insert:
 * @list: a pointer to a #GumList
 * @data: the data for the new element
 * @position: the position to insert the element. If this is 
 *     negative, or is larger than the number of elements in the 
 *     list, the new element is added on to the end of the list.
 * 
 * Inserts a new element into the list at the given position.
 *
 * Returns: the new start of the #GumList
 */
GumList*
gum_list_insert (GumList	*list,
	       gpointer	 data,
	       gint	 position)
{
  GumList *new_list;
  GumList *tmp_list;
  
  if (position < 0)
    return gum_list_append (list, data);
  else if (position == 0)
    return gum_list_prepend (list, data);
  
  tmp_list = gum_list_nth (list, position);
  if (!tmp_list)
    return gum_list_append (list, data);
  
  new_list = _gum_list_alloc ();
  new_list->data = data;
  new_list->prev = tmp_list->prev;
  if (tmp_list->prev)
    tmp_list->prev->next = new_list;
  new_list->next = tmp_list;
  tmp_list->prev = new_list;
  
  if (tmp_list == list)
    return new_list;
  else
    return list;
}

/**
 * gum_list_insert_before:
 * @list: a pointer to a #GumList
 * @sibling: the list element before which the new element 
 *     is inserted or %NULL to insert at the end of the list
 * @data: the data for the new element
 *
 * Inserts a new element into the list before the given position.
 *
 * Returns: the new start of the #GumList
 */
GumList*
gum_list_insert_before (GumList   *list,
		      GumList   *sibling,
		      gpointer data)
{
  if (!list)
    {
      list = gum_list_alloc ();
      list->data = data;
      g_return_val_if_fail (sibling == NULL, list);
      return list;
    }
  else if (sibling)
    {
      GumList *node;

      node = _gum_list_alloc ();
      node->data = data;
      node->prev = sibling->prev;
      node->next = sibling;
      sibling->prev = node;
      if (node->prev)
	{
	  node->prev->next = node;
	  return list;
	}
      else
	{
	  g_return_val_if_fail (sibling == list, node);
	  return node;
	}
    }
  else
    {
      GumList *last;

      last = list;
      while (last->next)
	last = last->next;

      last->next = _gum_list_alloc ();
      last->next->data = data;
      last->next->prev = last;
      last->next->next = NULL;

      return list;
    }
}

/**
 * gum_list_concat:
 * @list1: a #GumList
 * @list2: the #GumList to add to the end of the first #GumList
 *
 * Adds the second #GumList onto the end of the first #GumList.
 * Note that the elements of the second #GumList are not copied.
 * They are used directly.
 *
 * Returns: the start of the new #GumList
 */
GumList *
gum_list_concat (GumList *list1, GumList *list2)
{
  GumList *tmp_list;
  
  if (list2)
    {
      tmp_list = gum_list_last (list1);
      if (tmp_list)
	tmp_list->next = list2;
      else
	list1 = list2;
      list2->prev = tmp_list;
    }
  
  return list1;
}

/**
 * gum_list_remove:
 * @list: a #GumList
 * @data: the data of the element to remove
 *
 * Removes an element from a #GumList.
 * If two elements contain the same data, only the first is removed.
 * If none of the elements contain the data, the #GumList is unchanged.
 *
 * Returns: the new start of the #GumList
 */
GumList*
gum_list_remove (GumList	     *list,
	       gconstpointer  data)
{
  GumList *tmp;
  
  tmp = list;
  while (tmp)
    {
      if (tmp->data != data)
	tmp = tmp->next;
      else
	{
	  if (tmp->prev)
	    tmp->prev->next = tmp->next;
	  if (tmp->next)
	    tmp->next->prev = tmp->prev;
	  
	  if (list == tmp)
	    list = list->next;
	  
	  _gum_list_free1 (tmp);
	  
	  break;
	}
    }
  return list;
}

/**
 * gum_list_remove_all:
 * @list: a #GumList
 * @data: data to remove
 *
 * Removes all list nodes with data equal to @data. 
 * Returns the new head of the list. Contrast with 
 * gum_list_remove() which removes only the first node 
 * matching the given data.
 *
 * Returns: new head of @list
 */
GumList*
gum_list_remove_all (GumList	*list,
		   gconstpointer data)
{
  GumList *tmp = list;

  while (tmp)
    {
      if (tmp->data != data)
	tmp = tmp->next;
      else
	{
	  GumList *next = tmp->next;

	  if (tmp->prev)
	    tmp->prev->next = next;
	  else
	    list = next;
	  if (next)
	    next->prev = tmp->prev;

	  _gum_list_free1 (tmp);
	  tmp = next;
	}
    }
  return list;
}

static inline GumList*
_gum_list_remove_link (GumList *list,
		     GumList *link)
{
  if (link)
    {
      if (link->prev)
	link->prev->next = link->next;
      if (link->next)
	link->next->prev = link->prev;
      
      if (link == list)
	list = list->next;
      
      link->next = NULL;
      link->prev = NULL;
    }
  
  return list;
}

/**
 * gum_list_remove_link:
 * @list: a #GumList
 * @llink: an element in the #GumList
 *
 * Removes an element from a #GumList, without freeing the element.
 * The removed element's prev and next links are set to %NULL, so 
 * that it becomes a self-contained list with one element.
 *
 * Returns: the new start of the #GumList, without the element
 */
GumList*
gum_list_remove_link (GumList *list,
		    GumList *llink)
{
  return _gum_list_remove_link (list, llink);
}

/**
 * gum_list_delete_link:
 * @list: a #GumList
 * @link_: node to delete from @list
 *
 * Removes the node link_ from the list and frees it. 
 * Compare this to gum_list_remove_link() which removes the node 
 * without freeing it.
 *
 * Returns: the new head of @list
 */
GumList*
gum_list_delete_link (GumList *list,
		    GumList *link_)
{
  list = _gum_list_remove_link (list, link_);
  _gum_list_free1 (link_);

  return list;
}

/**
 * gum_list_copy:
 * @list: a #GumList
 *
 * Copies a #GumList.
 *
 * <note><para>
 * Note that this is a "shallow" copy. If the list elements 
 * consist of pointers to data, the pointers are copied but 
 * the actual data is not.
 * </para></note>
 *
 * Returns: a copy of @list
 */
GumList*
gum_list_copy (GumList *list)
{
  GumList *new_list = NULL;

  if (list)
    {
      GumList *last;

      new_list = _gum_list_alloc ();
      new_list->data = list->data;
      new_list->prev = NULL;
      last = new_list;
      list = list->next;
      while (list)
	{
	  last->next = _gum_list_alloc ();
	  last->next->prev = last;
	  last = last->next;
	  last->data = list->data;
	  list = list->next;
	}
      last->next = NULL;
    }

  return new_list;
}

/**
 * gum_list_reverse:
 * @list: a #GumList
 *
 * Reverses a #GumList.
 * It simply switches the next and prev pointers of each element.
 *
 * Returns: the start of the reversed #GumList
 */
GumList*
gum_list_reverse (GumList *list)
{
  GumList *last;
  
  last = NULL;
  while (list)
    {
      last = list;
      list = last->next;
      last->next = last->prev;
      last->prev = list;
    }
  
  return last;
}

/**
 * gum_list_nth:
 * @list: a #GumList
 * @n: the position of the element, counting from 0
 *
 * Gets the element at the given position in a #GumList.
 *
 * Returns: the element, or %NULL if the position is off 
 *     the end of the #GumList
 */
GumList*
gum_list_nth (GumList *list,
	    guint  n)
{
  while ((n-- > 0) && list)
    list = list->next;
  
  return list;
}

/**
 * gum_list_nth_prev:
 * @list: a #GumList
 * @n: the position of the element, counting from 0
 *
 * Gets the element @n places before @list.
 *
 * Returns: the element, or %NULL if the position is 
 *     off the end of the #GumList
 */
GumList*
gum_list_nth_prev (GumList *list,
		 guint  n)
{
  while ((n-- > 0) && list)
    list = list->prev;
  
  return list;
}

/**
 * gum_list_nth_data:
 * @list: a #GumList
 * @n: the position of the element
 *
 * Gets the data of the element at the given position.
 *
 * Returns: the element's data, or %NULL if the position 
 *     is off the end of the #GumList
 */
gpointer
gum_list_nth_data (GumList     *list,
		 guint      n)
{
  while ((n-- > 0) && list)
    list = list->next;
  
  return list ? list->data : NULL;
}

/**
 * gum_list_find:
 * @list: a #GumList
 * @data: the element data to find
 *
 * Finds the element in a #GumList which 
 * contains the given data.
 *
 * Returns: the found #GumList element, 
 *     or %NULL if it is not found
 */
GumList*
gum_list_find (GumList         *list,
	     gconstpointer  data)
{
  while (list)
    {
      if (list->data == data)
	break;
      list = list->next;
    }
  
  return list;
}

/**
 * gum_list_find_custom:
 * @list: a #GumList
 * @data: user data passed to the function
 * @func: the function to call for each element. 
 *     It should return 0 when the desired element is found
 *
 * Finds an element in a #GumList, using a supplied function to 
 * find the desired element. It iterates over the list, calling 
 * the given function which should return 0 when the desired 
 * element is found. The function takes two #gconstpointer arguments, 
 * the #GumList element's data as the first argument and the 
 * given user data.
 *
 * Returns: the found #GumList element, or %NULL if it is not found
 */
GumList*
gum_list_find_custom (GumList         *list,
		    gconstpointer  data,
		    GCompareFunc   func)
{
  g_return_val_if_fail (func != NULL, list);

  while (list)
    {
      if (! func (list->data, data))
	return list;
      list = list->next;
    }

  return NULL;
}


/**
 * gum_list_position:
 * @list: a #GumList
 * @llink: an element in the #GumList
 *
 * Gets the position of the given element 
 * in the #GumList (starting from 0).
 *
 * Returns: the position of the element in the #GumList, 
 *     or -1 if the element is not found
 */
gint
gum_list_position (GumList *list,
		 GumList *llink)
{
  gint i;

  i = 0;
  while (list)
    {
      if (list == llink)
	return i;
      i++;
      list = list->next;
    }

  return -1;
}

/**
 * gum_list_index:
 * @list: a #GumList
 * @data: the data to find
 *
 * Gets the position of the element containing 
 * the given data (starting from 0).
 *
 * Returns: the index of the element containing the data, 
 *     or -1 if the data is not found
 */
gint
gum_list_index (GumList         *list,
	      gconstpointer  data)
{
  gint i;

  i = 0;
  while (list)
    {
      if (list->data == data)
	return i;
      i++;
      list = list->next;
    }

  return -1;
}

/**
 * gum_list_last:
 * @list: a #GumList
 *
 * Gets the last element in a #GumList.
 *
 * Returns: the last element in the #GumList, 
 *     or %NULL if the #GumList has no elements
 */
GumList*
gum_list_last (GumList *list)
{
  if (list)
    {
      while (list->next)
	list = list->next;
    }
  
  return list;
}

/**
 * gum_list_first:
 * @list: a #GumList
 *
 * Gets the first element in a #GumList.
 *
 * Returns: the first element in the #GumList, 
 *     or %NULL if the #GumList has no elements
 */
GumList*
gum_list_first (GumList *list)
{
  if (list)
    {
      while (list->prev)
	list = list->prev;
    }
  
  return list;
}

/**
 * gum_list_length:
 * @list: a #GumList
 *
 * Gets the number of elements in a #GumList.
 *
 * <note><para>
 * This function iterates over the whole list to 
 * count its elements.
 * </para></note>
 *
 * Returns: the number of elements in the #GumList
 */
guint
gum_list_length (GumList *list)
{
  guint length;
  
  length = 0;
  while (list)
    {
      length++;
      list = list->next;
    }
  
  return length;
}

/**
 * gum_list_foreach:
 * @list: a #GumList
 * @func: the function to call with each element's data
 * @user_data: user data to pass to the function
 *
 * Calls a function for each element of a #GumList.
 */
void
gum_list_foreach (GumList	 *list,
		GFunc	  func,
		gpointer  user_data)
{
  while (list)
    {
      GumList *next = list->next;
      (*func) (list->data, user_data);
      list = next;
    }
}

static GumList*
gum_list_insert_sorted_real (GumList    *list,
			   gpointer  data,
			   GFunc     func,
			   gpointer  user_data)
{
  GumList *tmp_list = list;
  GumList *new_list;
  gint cmp;

  g_return_val_if_fail (func != NULL, list);
  
  if (!list) 
    {
      new_list = _gum_list_alloc0 ();
      new_list->data = data;
      return new_list;
    }
  
  cmp = ((GCompareDataFunc) func) (data, tmp_list->data, user_data);

  while ((tmp_list->next) && (cmp > 0))
    {
      tmp_list = tmp_list->next;

      cmp = ((GCompareDataFunc) func) (data, tmp_list->data, user_data);
    }

  new_list = _gum_list_alloc0 ();
  new_list->data = data;

  if ((!tmp_list->next) && (cmp > 0))
    {
      tmp_list->next = new_list;
      new_list->prev = tmp_list;
      return list;
    }
   
  if (tmp_list->prev)
    {
      tmp_list->prev->next = new_list;
      new_list->prev = tmp_list->prev;
    }
  new_list->next = tmp_list;
  tmp_list->prev = new_list;
 
  if (tmp_list == list)
    return new_list;
  else
    return list;
}

/**
 * gum_list_insert_sorted:
 * @list: a pointer to a #GumList
 * @data: the data for the new element
 * @func: the function to compare elements in the list. It should 
 *     return a number > 0 if the first parameter comes after the 
 *     second parameter in the sort order.
 *
 * Inserts a new element into the list, using the given comparison 
 * function to determine its position.
 *
 * Returns: the new start of the #GumList
 */
GumList*
gum_list_insert_sorted (GumList        *list,
		      gpointer      data,
		      GCompareFunc  func)
{
  return gum_list_insert_sorted_real (list, data, (GFunc) func, NULL);
}

/**
 * gum_list_insert_sorted_with_data:
 * @list: a pointer to a #GumList
 * @data: the data for the new element
 * @func: the function to compare elements in the list. 
 *     It should return a number > 0 if the first parameter 
 *     comes after the second parameter in the sort order.
 * @user_data: user data to pass to comparison function.
 *
 * Inserts a new element into the list, using the given comparison 
 * function to determine its position.
 *
 * Returns: the new start of the #GumList
 *
 * Since: 2.10
 */
GumList*
gum_list_insert_sorted_with_data (GumList            *list,
				gpointer          data,
				GCompareDataFunc  func,
				gpointer          user_data)
{
  return gum_list_insert_sorted_real (list, data, (GFunc) func, user_data);
}

static GumList *
gum_list_sort_merge (GumList     *l1, 
		   GumList     *l2,
		   GFunc     compare_func,
		   gpointer  user_data)
{
  GumList list, *l, *lprev;
  gint cmp;

  l = &list; 
  lprev = NULL;

  while (l1 && l2)
    {
      cmp = ((GCompareDataFunc) compare_func) (l1->data, l2->data, user_data);

      if (cmp <= 0)
        {
	  l->next = l1;
	  l1 = l1->next;
        } 
      else 
	{
	  l->next = l2;
	  l2 = l2->next;
        }
      l = l->next;
      l->prev = lprev; 
      lprev = l;
    }
  l->next = l1 ? l1 : l2;
  l->next->prev = l;

  return list.next;
}

static GumList* 
gum_list_sort_real (GumList    *list,
		  GFunc     compare_func,
		  gpointer  user_data)
{
  GumList *l1, *l2;
  
  if (!list) 
    return NULL;
  if (!list->next) 
    return list;
  
  l1 = list; 
  l2 = list->next;

  while ((l2 = l2->next) != NULL)
    {
      if ((l2 = l2->next) == NULL) 
	break;
      l1 = l1->next;
    }
  l2 = l1->next; 
  l1->next = NULL; 

  return gum_list_sort_merge (gum_list_sort_real (list, compare_func, user_data),
			    gum_list_sort_real (l2, compare_func, user_data),
			    compare_func,
			    user_data);
}

/**
 * gum_list_sort:
 * @list: a #GumList
 * @compare_func: the comparison function used to sort the #GumList.
 *     This function is passed the data from 2 elements of the #GumList 
 *     and should return 0 if they are equal, a negative value if the 
 *     first element comes before the second, or a positive value if 
 *     the first element comes after the second.
 *
 * Sorts a #GumList using the given comparison function.
 *
 * Returns: the start of the sorted #GumList
 */
GumList *
gum_list_sort (GumList        *list,
	     GCompareFunc  compare_func)
{
  return gum_list_sort_real (list, (GFunc) compare_func, NULL);
			    
}

/**
 * gum_list_sort_with_data:
 * @list: a #GumList
 * @compare_func: comparison function
 * @user_data: user data to pass to comparison function
 *
 * Like gum_list_sort(), but the comparison function accepts 
 * a user data argument.
 *
 * Returns: the new head of @list
 */
GumList *
gum_list_sort_with_data (GumList            *list,
		       GCompareDataFunc  compare_func,
		       gpointer          user_data)
{
  return gum_list_sort_real (list, (GFunc) compare_func, user_data);
}
