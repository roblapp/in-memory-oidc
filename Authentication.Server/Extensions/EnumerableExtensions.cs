namespace Authentication.Server.Extensions
{
    using System;
    using System.Collections.Generic;
    using System.Linq;

    public static class EnumerableExtensions
    {
        public static bool IsNullOrEmpty<T>(this IEnumerable<T> list)
        {
            return list == null || !list.Any();
        }

        public static IEnumerable<T> Filter<T, TKey>(this IEnumerable<T> items, Func<T, TKey> keySelector)
        {
            return items.Filter(keySelector, x => x);
        }

        public static IEnumerable<TReturn> Filter<T, TKey, TReturn>(this IEnumerable<T> items, Func<T, TKey> keySelector, Func<T, TReturn> valueSelector)
        {
            var map = new Dictionary<TKey, TReturn>();

            foreach (var item in items)
            {
                if (!map.ContainsKey(keySelector(item)))
                {
                    map.Add(keySelector(item), valueSelector(item));
                }
            }

            //return map.Select(x => x.Value);

            var result = new List<TReturn>();

            foreach (var entry in map)
            {
                result.Add(entry.Value);
            }

            return result;
        }

        public static ICollection<T> CopyAs<T>(this ICollection<T> existingEnumerable, Func<T, T> copyFunc)
        {
            var list = new List<T>();

            foreach (var item in existingEnumerable)
            {
                list.Add(copyFunc(item));
            }

            return list;
        }
    }
}
