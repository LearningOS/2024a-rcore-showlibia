1. 在完成本次实验的过程（含此前学习的过程）中，我曾分别与 **以下各位** 就（与本次实验相关的）以下方面做过交流，还在代码中对应的位置以注释形式记录了具体的交流对象及内容：

   > 

2. 此外，我也参考了 **以下资料** ，还在代码中对应的位置以注释形式记录了具体的参考来源及内容：

   > 

3. 我独立完成了本次实验除以上方面之外的所有工作，包括代码与文档。 我清楚地知道，从以上方面获得的信息在一定程度上降低了实验难度，可能会影响起评分。

4. 我从未使用过他人的代码，不管是原封不动地复制，还是经过了某些等价转换。 我未曾也不会向他人（含此后各届同学）复制或公开我的实验代码，我有义务妥善保管好它们。 我提交至本实验的评测系统的代码，均无意于破坏或妨碍任何计算机系统的正常运转。 我清楚地知道，以上情况均为本课程纪律所禁止，若违反，对应的实验成绩将按“-100”分计。

## 问答作业

- 实际上是轮到p2执行，因为p2.stride + pass = 260 = 4(8bit溢出)

- $ stride = stride + pass$ $ pass = \frac{BigStride}{priority} $

则有: $ stride \propto pass$ 也即 $ stride \propto \frac{BigStride}{priority}$

而优先级大于等于2，那么$ STRIDE\_MAX \leq  \frac{BigStride} 2$, STRIDE_MIN大于0，得证

- ```rust
  use core::cmp::Ordering;
  
  struct Stride(u64);
  
  impl PartialOrd for Stride {
      fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
          let stride_a = self.0;
          let stride_b = other.0;
          let half_stride = 127; // BigStride / 2 = 255 / 2 = 127
          
          // 如果 `stride_a` 与 `stride_b` 的差在半径之内，按正常大小比较
          if stride_a <= stride_b && stride_b - stride_a < half_stride {
              Some(Ordering::Less)
          } else if stride_a >= stride_b && stride_a - stride_b < half_stride {
              Some(Ordering::Greater)
          } else {
              // 否则，相对距离跨越了 `half_stride`，视为溢出反转的情况
              if stride_a < stride_b {
                  Some(Ordering::Greater)
              } else {
                  Some(Ordering::Less)
              }
          }
      }
  }
  
  impl PartialEq for Stride {
      fn eq(&self, other: &Self) -> bool {
          false
      }
  }
  ```

