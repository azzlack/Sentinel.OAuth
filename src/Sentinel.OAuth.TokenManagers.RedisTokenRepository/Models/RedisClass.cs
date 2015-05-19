namespace Sentinel.OAuth.TokenManagers.RedisTokenRepository.Models
{
    using System;
    using System.Collections.Generic;
    using System.Linq;

    using FastMember;

    using Newtonsoft.Json;

    using StackExchange.Redis;

    /// <summary>Base class for Redis entries.</summary>
    /// <typeparam name="T">The real type.</typeparam>
    public abstract class RedisClass<T>
    {
        /// <summary>The type key.</summary>
        public const string TypeKey = "__type";

        /// <summary>Initializes a new instance of the <see cref="RedisClass{T}"/> class.</summary>
        /// <param name="item">The item.</param>
        protected RedisClass(T item)
        {
            this.Type = item.GetType();
            this.Item = item;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RedisClass{T}"/> class.
        /// </summary>
        /// <exception cref="ArgumentException">
        /// Thrown when one or more arguments have unsupported or illegal values.
        /// </exception>
        /// <param name="hashEntries">The hash entries.</param>
        protected RedisClass(HashEntry[] hashEntries)
        {
            var typeEntry = hashEntries.FirstOrDefault(x => x.Name == TypeKey);

            if (typeEntry == null)
            {
                throw new ArgumentException("Unable to read the implementation type. Make sure the {0} parameter is set.", TypeKey);
            }

            var type = Type.GetType(typeEntry.Value);

            var accessor = TypeAccessor.Create(type);
            var item = accessor.CreateNew();

            var baseAccessor = TypeAccessor.Create(typeof(T));
            var baseMembers = baseAccessor.GetMembers();

            // Read out all IAccessToken members
            foreach (var member in baseMembers)
            {
                var hashEntry = hashEntries.FirstOrDefault(x => x.Name == member.Name);

                if (member.Type == typeof(string))
                {
                    accessor[item, member.Name] = hashEntry.Value.ToString();
                }
                else
                {
                    accessor[item, member.Name] = JsonConvert.DeserializeObject(hashEntry.Value.ToString(), member.Type);
                }
            }

            // Loop through all other members
            var otherMembers = accessor.GetMembers().Where(x => baseMembers.All(y => y.Name != x.Name));
            foreach (var member in otherMembers)
            {
                var hashEntry = hashEntries.FirstOrDefault(x => x.Name == member.Name);

                if (!hashEntry.Value.IsNull)
                {
                    accessor[item, member.Name] = JsonConvert.DeserializeObject(hashEntry.Value.ToString(), member.Type);
                }
            }

            this.Type = type;
            this.Item = (T)item;
        }

        /// <summary>Gets the type.</summary>
        /// <value>The type.</value>
        public Type Type { get; private set; }

        /// <summary>Gets  the item.</summary>
        /// <value>The item.</value>
        public T Item { get; private set; }

        /// <summary>Converts this object to a list of hash entries.</summary>
        /// <returns>This object as a Redis hash.</returns>
        public HashEntry[] ToHashEntries()
        {
            var entries = new List<HashEntry>() { new HashEntry(TypeKey, this.Type.AssemblyQualifiedName) };

            var accessor = TypeAccessor.Create(this.Item.GetType());

            if (!accessor.CreateNewSupported)
            {
                throw new ArgumentException("The underlying type must contain a parameterless constructor");
            }

            foreach (var member in accessor.GetMembers())
            {
                var value = accessor[this.Item, member.Name];

                if (value != null)
                {
                    if (member.Type == typeof(string))
                    {
                        entries.Add(new HashEntry(member.Name, value.ToString()));
                    }
                    else
                    {
                        entries.Add(new HashEntry(member.Name, JsonConvert.SerializeObject(value)));
                    }
                }
            }

            return entries.ToArray();
        }
    }
}